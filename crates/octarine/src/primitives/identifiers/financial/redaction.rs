//! Financial identifier redaction strategy types
//!
//! Domain-specific redaction strategies for financial data ensuring compile-time
//! type safety. Each financial identifier type has its own strategy enum with
//! only valid redaction options.
//!
//! ## PCI-DSS Compliance
//!
//! The Payment Card Industry Data Security Standard (PCI-DSS) Requirement 3.3
//! mandates that Primary Account Numbers (PANs) be masked when displayed:
//! - **Maximum 6 first digits** + **Maximum 4 last digits** may be displayed
//! - This module provides `ShowLast4` strategies for PCI-DSS compliance
//!
//! ## Design Philosophy
//!
//! Following the pattern from `personal/redaction.rs`:
//! - **Domain-specific types** prevent invalid combinations at compile time
//! - **Cannot** pass `BankAccountRedactionStrategy` to credit card functions
//! - **Cannot** use `ShowBrand` strategy for routing numbers
//! - **IDE autocomplete** shows only valid options per type
//!
//! ## Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::financial::redaction::{
//!     CreditCardRedactionStrategy, TextRedactionPolicy
//! };
//!
//! // Single identifier with specific strategy
//! let strategy = CreditCardRedactionStrategy::ShowLast4; // PCI-DSS compliant
//!
//! // Text scanning with generic policy
//! let policy = TextRedactionPolicy::Partial; // Maps to ShowLast4 for cards
//! ```

/// Credit card redaction strategies
///
/// PCI-DSS compliant options for displaying payment card numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditCardRedactionStrategy {
    /// Skip redaction (⚠️ Use only in development/testing)
    Skip,

    /// Show last 4 digits (PCI-DSS compliant)
    ///
    /// Example: `************1234`
    ///
    /// PCI-DSS 3.3: Compliant - masks first 12 digits
    ShowLast4,

    /// Show first 6 (BIN) + last 4 (PCI-DSS compliant)
    ///
    /// Example: `411111******1234`
    ///
    /// PCI-DSS 3.3: Compliant - shows max allowed digits
    ShowBinLast4,

    /// Show card brand only
    ///
    /// Example: `[VISA-****]` or `[MASTERCARD-****]`
    ShowBrand,

    /// Type token
    ///
    /// Example: `[CREDIT_CARD]`
    Token,

    /// Generic redaction token
    ///
    /// Example: `[REDACTED]`
    Anonymous,

    /// Asterisks (length-preserving)
    ///
    /// Example: `****************`
    Asterisks,

    /// Hashes (length-preserving)
    ///
    /// Example: `################`
    Hashes,
}

/// Bank account number redaction strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BankAccountRedactionStrategy {
    /// Skip redaction (⚠️ Use only in development/testing)
    Skip,

    /// Show last 4 digits
    ///
    /// Example: `******1234`
    ShowLast4,

    /// Type token
    ///
    /// Example: `[BANK_ACCOUNT]`
    Token,

    /// Generic redaction token
    ///
    /// Example: `[REDACTED]`
    Anonymous,

    /// Asterisks (length-preserving)
    ///
    /// Example: `**********`
    Asterisks,

    /// Hashes (length-preserving)
    ///
    /// Example: `##########`
    Hashes,
}

/// Routing number redaction strategies
///
/// US ABA routing numbers are less sensitive than account numbers but
/// should still be protected in logs and external displays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingNumberRedactionStrategy {
    /// Skip redaction (⚠️ Use only in development/testing)
    Skip,

    /// Type token
    ///
    /// Example: `[ROUTING]`
    Token,

    /// Generic redaction token
    ///
    /// Example: `[REDACTED]`
    Anonymous,

    /// Asterisks (length-preserving)
    ///
    /// Example: `*********`
    Asterisks,

    /// Hashes (length-preserving)
    ///
    /// Example: `#########`
    Hashes,
}

/// Payment token redaction strategies
///
/// Tokens (Stripe, PayPal, Braintree, etc.) are opaque identifiers
/// that should be redacted in logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentTokenRedactionStrategy {
    /// Skip redaction (⚠️ Use only in development/testing)
    Skip,

    /// Show last 4 characters
    ///
    /// Example: `tok_****************abcd`
    ShowLast4,

    /// Type token
    ///
    /// Example: `[PAYMENT_TOKEN]`
    Token,

    /// Generic redaction token
    ///
    /// Example: `[REDACTED]`
    Anonymous,

    /// Asterisks (length-preserving)
    ///
    /// Example: `********************`
    Asterisks,

    /// Hashes (length-preserving)
    ///
    /// Example: `####################`
    Hashes,
}

/// Generic redaction policy for text scanning
///
/// Provides a simplified API for scanning text and redacting all
/// financial identifiers consistently.
///
/// Each policy maps to sensible defaults for each identifier type:
/// - **Partial**: ShowLast4 for cards/accounts, Token for routing/tokens
/// - **Complete**: Type-specific tokens ([CREDIT_CARD], [BANK_ACCOUNT], etc.)
/// - **Anonymous**: Generic [REDACTED] for all types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction (⚠️ Use only in development/testing)
    Skip,

    /// Partial redaction - balance security and debuggability
    ///
    /// Maps to:
    /// - Credit cards → ShowLast4 (PCI-DSS compliant)
    /// - Bank accounts → ShowLast4
    /// - Routing numbers → Token
    /// - Payment tokens → ShowLast4
    Partial,

    /// Complete redaction - type-specific tokens
    ///
    /// Maps to:
    /// - Credit cards → Token ([CREDIT_CARD])
    /// - Bank accounts → Token ([BANK_ACCOUNT])
    /// - Routing numbers → Token ([ROUTING])
    /// - Payment tokens → Token ([PAYMENT_TOKEN])
    #[default]
    Complete,

    /// Anonymous redaction - generic token for all types
    ///
    /// Maps to: [REDACTED] for everything
    Anonymous,
}

impl TextRedactionPolicy {
    /// Map policy to credit card strategy
    #[must_use]
    pub const fn to_credit_card_strategy(self) -> CreditCardRedactionStrategy {
        match self {
            Self::Skip => CreditCardRedactionStrategy::Skip,
            Self::Partial => CreditCardRedactionStrategy::ShowLast4,
            Self::Complete => CreditCardRedactionStrategy::Token,
            Self::Anonymous => CreditCardRedactionStrategy::Anonymous,
        }
    }

    /// Map policy to bank account strategy
    #[must_use]
    pub const fn to_bank_account_strategy(self) -> BankAccountRedactionStrategy {
        match self {
            Self::Skip => BankAccountRedactionStrategy::Skip,
            Self::Partial => BankAccountRedactionStrategy::ShowLast4,
            Self::Complete => BankAccountRedactionStrategy::Token,
            Self::Anonymous => BankAccountRedactionStrategy::Anonymous,
        }
    }

    /// Map policy to routing number strategy
    #[must_use]
    pub const fn to_routing_strategy(self) -> RoutingNumberRedactionStrategy {
        match self {
            Self::Skip => RoutingNumberRedactionStrategy::Skip,
            Self::Partial => RoutingNumberRedactionStrategy::Token, // Routing less sensitive
            Self::Complete => RoutingNumberRedactionStrategy::Token,
            Self::Anonymous => RoutingNumberRedactionStrategy::Anonymous,
        }
    }

    /// Map policy to payment token strategy
    #[must_use]
    pub const fn to_payment_token_strategy(self) -> PaymentTokenRedactionStrategy {
        match self {
            Self::Skip => PaymentTokenRedactionStrategy::Skip,
            Self::Partial => PaymentTokenRedactionStrategy::ShowLast4,
            Self::Complete => PaymentTokenRedactionStrategy::Token,
            Self::Anonymous => PaymentTokenRedactionStrategy::Anonymous,
        }
    }
}
