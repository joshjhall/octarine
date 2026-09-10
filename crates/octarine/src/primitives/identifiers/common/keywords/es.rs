//! Spanish (`es`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/es`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Spanish (`es`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "número de seguridad social",
            "numero de seguridad social",
            "seguridad social",
            "número de la seguridad social",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &[
            "tarjeta de crédito",
            "tarjeta de credito",
            "tarjeta",
            "número de tarjeta",
            "numero de tarjeta",
            "tarjeta de débito",
            "tarjeta de debito",
            "visa",
            "mastercard",
        ],
    ),
    (
        IdentifierType::Email,
        &[
            "correo electrónico",
            "correo electronico",
            "correo",
            "email",
            "dirección de correo",
            "direccion de correo",
            "contacto",
        ],
    ),
    (
        IdentifierType::PhoneNumber,
        &[
            "teléfono",
            "telefono",
            "número de teléfono",
            "numero de telefono",
            "móvil",
            "movil",
            "celular",
        ],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "cuenta bancaria",
            "número de cuenta",
            "numero de cuenta",
            "cuenta corriente",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (
        IdentifierType::RoutingNumber,
        &["código bancario", "codigo bancario", "entidad bancaria"],
    ),
    (
        IdentifierType::DriverLicense,
        &[
            "permiso de conducir",
            "carnet de conducir",
            "licencia de conducir",
            "número de permiso",
        ],
    ),
    (
        IdentifierType::Passport,
        &[
            "pasaporte",
            "número de pasaporte",
            "numero de pasaporte",
            "pasaporte español",
        ],
    ),
    (
        IdentifierType::SpainPassport,
        &[
            "pasaporte",
            "número de pasaporte",
            "numero de pasaporte",
            "pasaporte español",
        ],
    ),
    (
        IdentifierType::Birthdate,
        &[
            "fecha de nacimiento",
            "nacido el",
            "nacida el",
            "cumpleaños",
            "cumpleanos",
        ],
    ),
    (
        IdentifierType::IpAddress,
        &["dirección ip", "direccion ip", "ip", "dirección de red"],
    ),
    (
        IdentifierType::ApiKey,
        &[
            "clave api",
            "clave de api",
            "clave secreta",
            "token de acceso",
        ],
    ),
    (
        IdentifierType::PersonalName,
        &["nombre", "apellido", "apellidos", "nombre completo"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "número de cuenta internacional", "bic", "swift"],
    ),
    (
        IdentifierType::SpainNif,
        &[
            "nif",
            "número de identificación fiscal",
            "numero de identificacion fiscal",
            "dni",
            "documento nacional de identidad",
            "cif",
            "nie",
        ],
    ),
];
