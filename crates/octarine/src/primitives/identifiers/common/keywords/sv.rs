//! Swedish (`sv`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/sv`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Swedish (`sv`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "personnummer",
            "personnr",
            "samordningsnummer",
            "socialförsäkringsnummer",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &[
            "kreditkort",
            "kortnummer",
            "betalkort",
            "bankkort",
            "visa",
            "mastercard",
        ],
    ),
    (
        IdentifierType::Email,
        &["e-postadress", "e-post", "epost", "mejl", "kontakt"],
    ),
    (
        IdentifierType::PhoneNumber,
        &["telefon", "telefonnummer", "mobil", "mobilnummer"],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "bankkonto",
            "kontonummer",
            "konto",
            "clearingnummer",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (
        IdentifierType::RoutingNumber,
        &["clearingnummer", "bankkod"],
    ),
    (
        IdentifierType::DriverLicense,
        &["körkort", "korkort", "körkortsnummer"],
    ),
    (
        IdentifierType::Passport,
        &["pass", "passnummer", "passhandling"],
    ),
    (
        IdentifierType::Birthdate,
        &["födelsedatum", "fodelsedatum", "född", "födelsedag"],
    ),
    (
        IdentifierType::IpAddress,
        &["ip-adress", "ip adress", "nätverksadress"],
    ),
    (
        IdentifierType::ApiKey,
        &["api-nyckel", "api nyckel", "hemlig nyckel", "token"],
    ),
    (
        IdentifierType::PersonalName,
        &["namn", "förnamn", "efternamn", "fullständigt namn"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "internationellt kontonummer", "bic", "swift"],
    ),
];
