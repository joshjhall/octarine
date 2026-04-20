//! Financial identifier types (credit card brands, etc.)

/// Credit card brand/type enumeration
///
/// Detected based on BIN (Bank Identification Number) patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditCardType {
    /// Visa cards - starts with 4, 13/16/19 digits
    Visa,
    /// Mastercard - starts with 51-55 or 2221-2720, 16 digits
    Mastercard,
    /// American Express - starts with 34 or 37, 15 digits
    AmericanExpress,
    /// Discover - starts with 6011, 644-649, or 65, 16 digits
    Discover,
    /// JCB (Japan Credit Bureau) - starts with 3528-3589, 16 digits
    Jcb,
    /// Diners Club - starts with 300-305, 36, or 38, 14 digits
    DinersClub,
    /// UnionPay - starts with 62 or 81, 16-19 digits
    UnionPay,
    /// Maestro - starts with 5018/5020/5038/5893/6304/6759/6761-6763, 12-19 digits
    Maestro,
    /// Verve (Nigerian) - starts with 506099-506198 or 650002-650027, 16-19 digits
    Verve,
    /// RuPay (India) - starts with 60/65/81/82/508, 16 digits
    RuPay,
    /// Unknown or unsupported card type
    Unknown,
}

impl std::fmt::Display for CreditCardType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Visa => write!(f, "Visa"),
            Self::Mastercard => write!(f, "Mastercard"),
            Self::AmericanExpress => write!(f, "American Express"),
            Self::Discover => write!(f, "Discover"),
            Self::Jcb => write!(f, "JCB"),
            Self::DinersClub => write!(f, "Diners Club"),
            Self::UnionPay => write!(f, "UnionPay"),
            Self::Maestro => write!(f, "Maestro"),
            Self::Verve => write!(f, "Verve"),
            Self::RuPay => write!(f, "RuPay"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}
