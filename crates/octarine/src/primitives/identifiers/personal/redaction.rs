//! Redaction strategy types for personal identifiers
//!
//! This module provides type-safe redaction strategies with two tiers:
//! 1. **Domain-specific enums** - Strict, type-safe strategies for single identifiers
//! 2. **Generic policy enum** - Simple, consistent policy for text scanning
//!
//! # Domain-Specific Strategies
//!
//! Each identifier type has its own strategy enum with only valid options:
//! - `EmailRedactionStrategy` - ShowFirst, ShowDomain, Token, etc.
//! - `PhoneRedactionStrategy` - ShowLastFour, ShowCountryCode, Token, etc.
//! - `NameRedactionStrategy` - ShowInitials, ShowFirst, Token, etc.
//! - `BirthdateRedactionStrategy` - ShowYear, Token, etc.
//! - `UsernameRedactionStrategy` - ShowFirstAndLast, ShowFirst, Token, etc.
//!
//! # Text Redaction Policy
//!
//! For scanning text with multiple identifier types, use `TextRedactionPolicy`:
//! - `None` - Skip redaction
//! - `Partial` - Show some information (sensible defaults per type)
//! - `Complete` - Full token redaction ([EMAIL], [PHONE], etc.)
//! - `Anonymous` - Generic [REDACTED] for everything
//!
//! Each `*_in_text()` function internally maps the policy to appropriate domain strategies.

/// Email-specific redaction strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailRedactionStrategy {
    /// Skip redaction - return as-is
    Skip,
    /// Show first character of local part: u***@example.com
    ShowFirst,
    /// Show domain only: ****@example.com
    ShowDomain,
    /// Replace with [EMAIL] token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Phone number redaction strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneRedactionStrategy {
    /// Skip redaction - return as-is
    Skip,
    /// Show last four digits: ***-***-4567 (PCI-DSS compliant)
    ShowLastFour,
    /// Show country code only: +1-***-***-****
    ShowCountryCode,
    /// Replace with [PHONE] token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Name redaction strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRedactionStrategy {
    /// Skip redaction - return as-is
    Skip,
    /// Show initials only: J.S.
    ShowInitials,
    /// Show first name only: John ***
    ShowFirst,
    /// Replace with [NAME] token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Birthdate redaction strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BirthdateRedactionStrategy {
    /// Skip redaction - return as-is
    Skip,
    /// Show year only: ****-**-** (1990)
    ShowYear,
    /// Replace with [DATE] token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Username redaction strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameRedactionStrategy {
    /// Skip redaction - return as-is
    Skip,
    /// Show first and last characters: j******e
    ShowFirstAndLast,
    /// Show first character only: j*******
    ShowFirst,
    /// Replace with [USERNAME] token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Generic redaction policy for text scanning across multiple identifier types
///
/// This simple enum provides a consistent policy when scanning text that may contain
/// multiple types of identifiers. Each `*_in_text()` function maps the policy to
/// appropriate domain-specific strategies.
///
/// # Policy Mappings
///
/// - `Partial` maps to sensible defaults per identifier:
///   - Email: `ShowFirst` (u***@example.com)
///   - Phone: `ShowLastFour` (***-***-4567, PCI-DSS compliant)
///   - Name: `ShowInitials` (J.S.)
///   - Birthdate: `ShowYear` (****-**-** (1990))
///   - Username: `ShowFirstAndLast` (j******e)
///
/// - `Complete` maps to token variants:
///   - `[EMAIL]`, `[PHONE]`, `[NAME]`, `[DATE]`, `[USERNAME]`
///
/// - `Anonymous` maps to generic `[REDACTED]` for all types
///
/// - `None` passes through unchanged
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction - pass through unchanged
    Skip,
    /// Partial redaction with sensible defaults (show some information)
    Partial,
    /// Complete redaction with type-specific tokens (`[EMAIL]`, `[PHONE]`, etc.)
    #[default]
    Complete,
    /// Anonymous redaction with generic `[REDACTED]` for all types
    Anonymous,
}

impl TextRedactionPolicy {
    /// Map text policy to email strategy
    #[must_use]
    pub const fn to_email_strategy(self) -> EmailRedactionStrategy {
        match self {
            Self::Skip => EmailRedactionStrategy::Skip,
            Self::Partial => EmailRedactionStrategy::ShowFirst,
            Self::Complete => EmailRedactionStrategy::Token,
            Self::Anonymous => EmailRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to phone strategy
    #[must_use]
    pub const fn to_phone_strategy(self) -> PhoneRedactionStrategy {
        match self {
            Self::Skip => PhoneRedactionStrategy::Skip,
            Self::Partial => PhoneRedactionStrategy::ShowLastFour,
            Self::Complete => PhoneRedactionStrategy::Token,
            Self::Anonymous => PhoneRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to name strategy
    #[must_use]
    pub const fn to_name_strategy(self) -> NameRedactionStrategy {
        match self {
            Self::Skip => NameRedactionStrategy::Skip,
            Self::Partial => NameRedactionStrategy::ShowInitials,
            Self::Complete => NameRedactionStrategy::Token,
            Self::Anonymous => NameRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to birthdate strategy
    #[must_use]
    pub const fn to_birthdate_strategy(self) -> BirthdateRedactionStrategy {
        match self {
            Self::Skip => BirthdateRedactionStrategy::Skip,
            Self::Partial => BirthdateRedactionStrategy::ShowYear,
            Self::Complete => BirthdateRedactionStrategy::Token,
            Self::Anonymous => BirthdateRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to username strategy
    #[must_use]
    pub const fn to_username_strategy(self) -> UsernameRedactionStrategy {
        match self {
            Self::Skip => UsernameRedactionStrategy::Skip,
            Self::Partial => UsernameRedactionStrategy::ShowFirstAndLast,
            Self::Complete => UsernameRedactionStrategy::Token,
            Self::Anonymous => UsernameRedactionStrategy::Anonymous,
        }
    }
}
