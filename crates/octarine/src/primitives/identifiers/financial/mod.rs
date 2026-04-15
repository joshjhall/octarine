//! Financial identifier detection, validation, and sanitization
//!
//! This module provides pure functions for financial identifiers:
//! - **Detection**: Find credit cards, routing numbers, bank accounts, payment tokens
//! - **Validation**: Verify format and validity (Luhn, ABA checksum)
//! - **Sanitization**: Redact and mask financial data
//! - **Conversion**: Normalize card formats
//!
//! # Compliance Coverage
//!
//! Financial identifiers handled by this module are protected under:
//!
//! | Identifier | PCI DSS | GDPR | CCPA |
//! |------------|---------|------|------|
//! | Credit Card | Requirement 3 | Art. 4(1) | Personal information |
//! | Bank Account | Best Practice | Art. 4(1) | Personal information |
//! | Routing Number | Best Practice | Art. 4(1) | Personal information |
//! | Payment Token | Requirement 3 | Art. 4(1) | Personal information |
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! # Usage
//!
//! Access functionality through the builder:
//!
//! ```rust,ignore
//! use octarine::primitives::identifiers::IdentifierBuilder;
//!
//! let builder = IdentifierBuilder::new();
//! let financial = builder.financial();
//!
//! // Detection
//! let is_card = financial.is_credit_card("4242424242424242");
//! let cards = financial.find_credit_cards_in_text("Card: 4242-4242-4242-4242");
//!
//! // Validation (coming soon)
//! // let valid = financial.validate_credit_card("4242424242424242");
//!
//! // Sanitization (coming soon)
//! // let redacted = financial.redact_credit_card("4242424242424242");
//! ```
//!
//! # Performance Characteristics
//!
//! ## Computational Complexity
//!
//! | Operation | Time | Space | Notes |
//! |-----------|------|-------|-------|
//! | `is_credit_card` | O(n) | O(n) | Luhn checksum validation |
//! | `validate_routing_number` | O(1) | O(1) | ABA checksum (9 digits) |
//! | `find_credit_cards_in_text` | O(n) | O(m) | n = text length, m = matches |
//! | `find_routing_numbers_in_text` | O(n) | O(m) | n = text length, m = matches |
//! | `redact_credit_card` | O(n) | O(n) | n = card length |
//! | `mask_bank_account` | O(n) | O(n) | n = account length |
//!
//! ## Memory Usage
//!
//! - **Regex patterns**: ~10KB lazily initialized (shared across calls)
//! - **Per-call overhead**: Minimal, typically < 1KB for single identifiers
//! - **Text scanning**: Linear with text size plus detected matches
//!
//! ## Recommendations
//!
//! - For large documents (>1MB), consider async batch processing from Layer 3
//! - Use `Cow<str>` returns when possible to avoid allocations on clean text
//! - Cache builder instances for repeated operations

pub(crate) mod builder;
pub(crate) mod redaction;

// Internal modules - not directly accessible outside financial/
mod conversion;
mod detection;
mod sanitization;
mod validation;

// Re-export builder for convenient access
pub use builder::FinancialIdentifierBuilder;

// Re-export redaction strategies for type-safe redaction API
pub use redaction::{
    BankAccountRedactionStrategy, CreditCardRedactionStrategy, PaymentTokenRedactionStrategy,
    RoutingNumberRedactionStrategy, TextRedactionPolicy,
};

// Re-export types from shared types module (needed for builder return types)
pub use super::types::CreditCardType;

// Export cache stats functions for performance monitoring
pub use detection::{aba_cache_stats, clear_financial_caches, luhn_cache_stats};

// Export test pattern detection functions (observe module testing)
pub use detection::is_test_credit_card;

// Export detection functions
pub use detection::{is_financial_present, is_payment_data_present};

// Export validation functions
pub use validation::{
    validate_account_number, validate_bank_account, validate_credit_card, validate_routing_number,
};

// Export sanitization functions with strategy support
pub use sanitization::{
    redact_all_financial_in_text_with_policy, redact_bank_account_with_strategy,
    redact_bank_accounts_in_text_with_strategy, redact_credit_card_with_strategy,
    redact_credit_cards_in_text_with_strategy, redact_payment_token_with_strategy,
    redact_payment_tokens_in_text_with_strategy, redact_routing_number_with_strategy,
};
