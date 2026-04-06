//! Financial identification patterns
//!
//! Regex patterns for financial identifiers including credit cards, payment tokens,
//! routing numbers, and bank accounts.

// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
#![allow(clippy::expect_used)]

use once_cell::sync::Lazy;
use regex::Regex;

pub mod credit_card {
    use super::*;

    /// Credit card with spaces (4 groups of 4)
    /// Example: "4532 0151 1283 0366"
    pub static WITH_SPACES: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b").expect("BUG: Invalid regex pattern")
    });

    /// Credit card with dashes
    /// Example: "4532-0151-1283-0366"
    pub static WITH_DASHES: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b").expect("BUG: Invalid regex pattern")
    });

    /// Credit card without separators (16 digits)
    /// Example: "4532015112830366"
    pub static NO_SEPARATOR: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{16}\b").expect("BUG: Invalid regex pattern"));

    /// Labeled credit card
    /// Example: "Card: 4532015112830366"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i:card|cc|credit)[\s#:-]*(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})")
            .expect("BUG: Invalid regex pattern")
    });

    /// Generic credit card pattern (13-19 digits, flexible formatting)
    /// Example: "4532015112830366", "4532-0151-1283-0366"
    pub static GENERIC: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{4}[\s\-]?\d{4,6}[\s\-]?\d{4,5}[\s\-]?\d{2,4}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Formatted credit card pattern for text scanning
    /// Example: "4532 0151 1283 0366" or "4532-0151-1283-0366"
    pub static FORMATTED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{3,4}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Credit card digit-only pattern (13-19 digits, for validation)
    /// Example: "4532015112830366"
    pub static DIGITS_ONLY: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\d{13,19}$").expect("BUG: Invalid regex pattern"));

    /// Credit card formatted pattern for validation (allows spaces/dashes)
    /// Example: "4532-0151-1283-0366"
    pub static FORMATTED_VALIDATION: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7}$")
            .expect("BUG: Invalid regex pattern")
    });

    /// Payment context keywords for confidence scoring
    pub static CONTEXT_KEYWORDS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)card|credit|debit|payment|visa|mastercard|amex|discover|jcb|diners|unionpay|maestro|verve|rupay")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*WITH_SPACES, &*WITH_DASHES, &*NO_SEPARATOR]
    }

    /// Card brand validation patterns (for strict validation)
    pub mod brand {
        use super::*;

        /// Visa: Starts with 4, 13 or 16 digits
        pub static VISA: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^4[0-9]{12}(?:[0-9]{3})?$").expect("BUG: Invalid regex pattern")
        });

        /// Mastercard: Starts with 51-55 or 2221-2720, 16 digits
        pub static MASTERCARD: Lazy<Regex> = Lazy::new(|| {
            Regex::new(
                r"^(?:5[1-5][0-9]{14}|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[0-1][0-9]|720)[0-9]{12})$",
            )
            .expect("BUG: Invalid regex pattern")
        });

        /// American Express: Starts with 34 or 37, 15 digits
        pub static AMEX: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^3[47][0-9]{13}$").expect("BUG: Invalid regex pattern"));

        /// Discover: Starts with 6011, 622126-622925, 644-649, or 65, 16-19 digits
        pub static DISCOVER: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^6(?:011|5[0-9]{2})[0-9]{12,15}$").expect("BUG: Invalid regex pattern")
        });

        /// JCB: Starts with 2131, 1800, or 35, 15-19 digits
        pub static JCB: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(?:2131|1800|35\d{3})\d{11,15}$").expect("BUG: Invalid regex pattern")
        });

        /// Diners Club: Starts with 300-305, 36, or 38, 14 digits
        pub static DINERS: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^3(?:0[0-5]|[68][0-9])[0-9]{11}$").expect("BUG: Invalid regex pattern")
        });
    }
}

/// Payment token patterns (Stripe, PayPal, etc.)
pub mod payment_token {
    use super::*;

    /// Stripe tokens (various types)
    /// Examples: "tok_1234...", "pm_1234...", "pi_1234..."
    pub static STRIPE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(tok|pm|pi|seti|si|src)_[A-Za-z0-9]{24,}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// PayPal tokens
    /// Example: "EC-12345678901234567"
    pub static PAYPAL: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\bEC-[A-Z0-9]{17}\b").expect("BUG: Invalid regex pattern"));

    pub fn all() -> Vec<&'static Regex> {
        vec![&*STRIPE, &*PAYPAL]
    }
}

/// Routing number patterns
pub mod routing_number {
    use super::*;

    /// Standalone routing number (9 digits with word boundary)
    /// Example: "Routing: 021000021"
    pub static STANDALONE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{9}\b").expect("BUG: Invalid regex pattern"));

    /// Labeled routing number
    /// Example: "Routing Number: 021000021" or "ABA: 021000021"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i:routing|aba|rtn)[\s#:-]*(\d{9})\b").expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*STANDALONE, &*LABELED]
    }
}

/// Bank account patterns
pub mod bank_account {
    use super::*;

    /// IBAN format: 2 letters + 2 check digits + 11-30 alphanumeric BBAN
    /// Handles with/without spaces. Length 15-34 chars (varies by country).
    /// Example: "GB82 WEST 1234 5698 7654 32", "DE89370400440532013000"
    pub static IBAN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}(?:[\s]?[A-Z0-9]{4}){1,7}(?:[\s]?[A-Z0-9]{1,4})?\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    /// US routing + account (generic pattern)
    /// Example: "Routing: 123456789 Account: 1234567890"
    pub static US_ROUTING_ACCOUNT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i:routing)[\s#:-]*(\d{9}).*?(?i:account)[\s#:-]*(\d{4,17})")
            .expect("BUG: Invalid regex pattern")
    });

    /// Generic account number with label
    /// Example: "Account: 1234567890"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i:account)[\s#:-]*(\d{8,17})").expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*IBAN, &*US_ROUTING_ACCOUNT, &*LABELED]
    }
}

/// Cryptocurrency wallet address patterns
pub mod crypto {
    use super::*;

    /// Bitcoin P2PKH (Legacy) address: starts with '1', Base58Check
    /// Example: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    pub static BITCOIN_P2PKH: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b").expect("BUG: Invalid regex pattern")
    });

    /// Bitcoin P2SH (Script Hash) address: starts with '3', Base58Check
    /// Example: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    pub static BITCOIN_P2SH: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b").expect("BUG: Invalid regex pattern")
    });

    /// Bitcoin Bech32 (SegWit/Taproot) address: starts with 'bc1', lowercase
    /// Example: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    pub static BITCOIN_BECH32: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\bbc1[ac-hj-np-z02-9]{8,87}\b").expect("BUG: Invalid regex pattern")
    });

    /// Ethereum address: 0x followed by 40 hex characters
    /// Example: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
    pub static ETHEREUM: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b0x[a-fA-F0-9]{40}\b").expect("BUG: Invalid regex pattern"));

    pub fn all() -> Vec<&'static Regex> {
        vec![
            &*BITCOIN_P2PKH,
            &*BITCOIN_P2SH,
            &*BITCOIN_BECH32,
            &*ETHEREUM,
        ]
    }
}
