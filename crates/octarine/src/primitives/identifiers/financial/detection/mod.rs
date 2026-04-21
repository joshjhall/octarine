//! Financial identifier detection (primitives layer)
//!
//! Pure detection functions for financial identifiers with no observe dependencies.
//! Used by observe/pii and security modules.
//!
//! # Supported Identifiers
//!
//! - **Credit Cards**: Luhn checksum, BIN validation, brand detection, entropy analysis
//! - **Routing Numbers**: ABA checksum validation, Federal Reserve district checking
//! - **Bank Accounts**: Heuristic detection for account numbers (8-17 digits)
//! - **Payment Tokens**: Stripe, PayPal token patterns
//!
//! # Module Structure
//!
//! - `cache` - Shared caching infrastructure
//! - `credit_card` - Credit card detection and validation
//! - `routing` - ABA routing number detection
//! - `bank_account` - Bank account and IBAN detection
//! - `common` - Aggregate detection and text scanning

mod bank_account;
mod cache;
mod common;
mod credit_card;
mod crypto;
mod iban;
mod routing;

// Re-export cache utilities
pub use cache::{aba_cache_stats, clear_financial_caches, luhn_cache_stats};

// Re-export credit card functions
pub use credit_card::{
    detect_card_brand, detect_credit_card_with_context, detect_credit_cards_in_text,
    is_credit_card, is_credit_card_likely, is_credit_card_pattern, is_test_credit_card,
};

// Re-export routing number functions
pub use routing::{detect_routing_number, detect_routing_numbers_in_text, is_routing_number};

// Re-export bank account functions
pub use bank_account::{detect_bank_accounts_in_text, is_bank_account};

// Re-export payment token functions (in bank_account module for now)
pub use bank_account::detect_payment_tokens_in_text;

// Re-export IBAN functions
pub use iban::{detect_iban_country, detect_ibans_in_text, is_iban, is_iban_checksum_valid};

// Re-export crypto functions
pub use crypto::{
    detect_crypto_addresses_in_text, is_bitcoin_address, is_crypto_address, is_ethereum_address,
};

// Re-export common/aggregate functions
pub use common::{
    detect_all_financial_in_text, detect_financial_identifier, find_financial_identifier,
    is_financial_identifier, is_financial_present, is_payment_data_present,
};
