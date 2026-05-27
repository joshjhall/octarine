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

/// Cryptocurrency address type/chain enumeration.
///
/// Returned by `validate_crypto_address` after both shape detection and
/// checksum verification have succeeded. Distinguishes between Bitcoin
/// address kinds (P2PKH, P2SH, SegWit, Taproot) and between the two
/// flavors of Ethereum address (no-checksum vs EIP-55 mixed case).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAddressType {
    /// Bitcoin P2PKH (legacy) — Base58Check, starts with `1`.
    BitcoinP2PKH,
    /// Bitcoin P2SH (script hash) — Base58Check, starts with `3`.
    BitcoinP2SH,
    /// Bitcoin SegWit v0 — Bech32, starts with `bc1q`.
    BitcoinSegWit,
    /// Bitcoin Taproot (SegWit v1) — Bech32m, starts with `bc1p`.
    BitcoinTaproot,
    /// Ethereum address with all-lowercase or all-uppercase hex
    /// (EIP-55 checksum not enforced).
    EthereumLowercase,
    /// Ethereum address with valid EIP-55 mixed-case checksum.
    EthereumChecksum,
}

impl std::fmt::Display for CryptoAddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BitcoinP2PKH => write!(f, "Bitcoin P2PKH"),
            Self::BitcoinP2SH => write!(f, "Bitcoin P2SH"),
            Self::BitcoinSegWit => write!(f, "Bitcoin SegWit"),
            Self::BitcoinTaproot => write!(f, "Bitcoin Taproot"),
            Self::EthereumLowercase => write!(f, "Ethereum (no checksum)"),
            Self::EthereumChecksum => write!(f, "Ethereum (EIP-55)"),
        }
    }
}
