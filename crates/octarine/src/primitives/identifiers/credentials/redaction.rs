//! Credential redaction strategies (primitives layer)
//!
//! Type-safe redaction strategies for credential identifiers with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - defines redaction strategies with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Type-safe strategy enums
//!
//! # Design Pattern: Two-Tier Strategy Architecture
//!
//! ## Tier 1: Domain-Specific Strategies (For Individual Credentials)
//!
//! Each credential type has its own strategy enum:
//! - `PasswordRedactionStrategy` - For passwords
//! - `PinRedactionStrategy` - For PINs
//! - `SecurityAnswerRedactionStrategy` - For security question answers
//! - `PassphraseRedactionStrategy` - For passphrases
//!
//! ## Tier 2: Generic Text Policy (For Text Scanning)
//!
//! `TextRedactionPolicy` provides a simpler interface for text scanning.

/// Password redaction strategies
///
/// Controls how passwords are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordRedactionStrategy {
    /// Skip redaction - return original (DANGEROUS - use only in tests)
    Skip,
    /// Token placeholder: `[PASSWORD]`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Fixed-length asterisks: `********`
    Asterisks,
    /// Fixed-length hashes: `########`
    Hashes,
}

/// PIN redaction strategies
///
/// Controls how PINs are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRedactionStrategy {
    /// Skip redaction - return original (DANGEROUS - use only in tests)
    Skip,
    /// Token placeholder: `[PIN]`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Fixed-length asterisks: `****`
    Asterisks,
    /// Show length: `[PIN:4]`
    ShowLength,
}

/// Security answer redaction strategies
///
/// Controls how security question answers are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAnswerRedactionStrategy {
    /// Skip redaction - return original (DANGEROUS - use only in tests)
    Skip,
    /// Token placeholder: `[SECURITY_ANSWER]`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Fixed-length asterisks: `********`
    Asterisks,
}

/// Passphrase redaction strategies
///
/// Controls how passphrases are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseRedactionStrategy {
    /// Skip redaction - return original (DANGEROUS - use only in tests)
    Skip,
    /// Token placeholder: `[PASSPHRASE]`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Fixed-length asterisks: `********`
    Asterisks,
    /// Show word count: `[PASSPHRASE:4 words]`
    ShowWordCount,
}

/// Generic credential redaction strategy
///
/// Used when the specific credential type is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRedactionStrategy {
    /// Skip redaction - return original (DANGEROUS - use only in tests)
    Skip,
    /// Token placeholder based on detected type
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Fixed-length asterisks: `********`
    Asterisks,
}

/// Generic redaction policy for text scanning
///
/// Simpler interface that maps to domain-specific strategies.
/// Used by `*_in_text()` functions for consistent text redaction.
///
/// # Policy Mappings
///
/// - `Partial` maps to safe partial reveals per credential type:
///   - Password: `Asterisks` (shows length as `********`)
///   - PIN: `ShowLength` (shows `[PIN:4]`)
///   - Security Answer: `Asterisks` (shows length)
///   - Passphrase: `ShowWordCount` (shows `[PASSPHRASE:4 words]`)
///
/// - `Complete` maps to type-specific tokens:
///   - `[PASSWORD]`, `[PIN]`, `[SECURITY_ANSWER]`, `[PASSPHRASE]`
///
/// - `Anonymous` maps to generic `[REDACTED]` for all types
///
/// - `None` passes through unchanged (DANGEROUS - testing only)
///
/// # Security Note
///
/// Unlike personal identifiers (email, phone) where partial info is useful,
/// credentials should generally use `Complete` or `Anonymous` in production.
/// `Partial` reveals length information which could aid attackers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction (DANGEROUS - testing only)
    Skip,
    /// Partial redaction showing length/structure (use with caution)
    Partial,
    /// Complete redaction with type-specific tokens
    #[default]
    Complete,
    /// Anonymous redaction with generic `[REDACTED]`
    Anonymous,
}

impl TextRedactionPolicy {
    /// Convert policy to password strategy
    #[must_use]
    pub const fn to_password_strategy(self) -> PasswordRedactionStrategy {
        match self {
            Self::Skip => PasswordRedactionStrategy::Skip,
            Self::Partial => PasswordRedactionStrategy::Asterisks,
            Self::Complete => PasswordRedactionStrategy::Token,
            Self::Anonymous => PasswordRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to PIN strategy
    #[must_use]
    pub const fn to_pin_strategy(self) -> PinRedactionStrategy {
        match self {
            Self::Skip => PinRedactionStrategy::Skip,
            Self::Partial => PinRedactionStrategy::ShowLength,
            Self::Complete => PinRedactionStrategy::Token,
            Self::Anonymous => PinRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to security answer strategy
    #[must_use]
    pub const fn to_security_answer_strategy(self) -> SecurityAnswerRedactionStrategy {
        match self {
            Self::Skip => SecurityAnswerRedactionStrategy::Skip,
            Self::Partial => SecurityAnswerRedactionStrategy::Asterisks,
            Self::Complete => SecurityAnswerRedactionStrategy::Token,
            Self::Anonymous => SecurityAnswerRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to passphrase strategy
    #[must_use]
    pub const fn to_passphrase_strategy(self) -> PassphraseRedactionStrategy {
        match self {
            Self::Skip => PassphraseRedactionStrategy::Skip,
            Self::Partial => PassphraseRedactionStrategy::ShowWordCount,
            Self::Complete => PassphraseRedactionStrategy::Token,
            Self::Anonymous => PassphraseRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to generic credential strategy
    #[must_use]
    pub const fn to_credential_strategy(self) -> CredentialRedactionStrategy {
        match self {
            Self::Skip => CredentialRedactionStrategy::Skip,
            Self::Partial => CredentialRedactionStrategy::Asterisks,
            Self::Complete => CredentialRedactionStrategy::Token,
            Self::Anonymous => CredentialRedactionStrategy::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_text_policy_to_password_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_password_strategy(),
            PasswordRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_password_strategy(),
            PasswordRedactionStrategy::Asterisks
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_password_strategy(),
            PasswordRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_password_strategy(),
            PasswordRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_pin_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_pin_strategy(),
            PinRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_pin_strategy(),
            PinRedactionStrategy::ShowLength
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_pin_strategy(),
            PinRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_pin_strategy(),
            PinRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_passphrase_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_passphrase_strategy(),
            PassphraseRedactionStrategy::ShowWordCount
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_passphrase_strategy(),
            PassphraseRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_security_answer_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_security_answer_strategy(),
            SecurityAnswerRedactionStrategy::Asterisks
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_security_answer_strategy(),
            SecurityAnswerRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_credential_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_credential_strategy(),
            CredentialRedactionStrategy::Asterisks
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_credential_strategy(),
            CredentialRedactionStrategy::Token
        );
    }
}
