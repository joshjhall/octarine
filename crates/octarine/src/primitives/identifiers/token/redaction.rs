//! Token identifier redaction strategies (primitives layer)
//!
//! Type-safe redaction strategies for token identifiers with NO logging.
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
//! ## Tier 1: Domain-Specific Strategies (For Individual Identifiers)
//!
//! Each token identifier type has its own strategy enum with specific options:
//! - `JwtRedactionStrategy` - For single JWTs
//! - `ApiKeyRedactionStrategy` - For single API keys
//! - `SessionIdRedactionStrategy` - For single session IDs
//! - `SshKeyRedactionStrategy` - For single SSH keys
//! - `SshFingerprintRedactionStrategy` - For single SSH fingerprints
//!
//! ## Tier 2: Generic Text Policy (For Text Scanning)
//!
//! `TextRedactionPolicy` provides a simpler, generic interface for text scanning:
//! - Maps to appropriate domain strategy for each identifier type
//! - Used by `*_in_text()` functions
//! - Consistent across all identifier types
//!
//! # Security & Compliance
//!
//! Token identifiers are security-critical:
//! - **JWTs**: Contain user claims and signatures - PCI DSS, SOC2
//! - **Session IDs**: Enable session hijacking - OWASP A01:2021
//! - **API Keys**: Unauthorized access risk - PCI DSS Level 1 Data
//! - **SSH Keys**: Server access compromise - Critical infrastructure
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::token::{
//!     JwtRedactionStrategy, TextRedactionPolicy, redact_jwt, redact_jwts_in_text
//! };
//!
//! // Individual identifier with specific strategy
//! let redacted = redact_jwt("eyJhbGc...", JwtRedactionStrategy::ShowAlgorithm);
//! // Result: "<JWT-HS256>"
//!
//! // Text scanning with generic policy
//! let redacted = redact_jwts_in_text(
//!     "Token: eyJhbGc...",
//!     TextRedactionPolicy::Complete
//! );
//! // Result: "Token: <JWT>"
//! ```

/// JWT redaction strategies
///
/// Controls how JSON Web Tokens are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show algorithm only: `<JWT-HS256>` or `<JWT-RS256>`
    ShowAlgorithm,
    /// Show header only (first part before first dot)
    ShowHeader,
    /// Token placeholder: `<JWT>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// API key redaction strategies
///
/// Controls how API keys are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show provider: `<STRIPE_KEY>`, `<AWS_KEY>`, `<GITHUB_TOKEN>`
    ShowProvider,
    /// Show prefix: `sk_live_****`, `AKIA****`, `ghp_****`
    ShowPrefix,
    /// Mask (first 12 chars): `sk_live_1234***`
    Mask,
    /// Token placeholder: `<API_KEY>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Session ID redaction strategies
///
/// Controls how session identifiers are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionIdRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show prefix (first 8 chars): `a1b2c3d4****`
    ShowPrefix,
    /// Token placeholder: `<SESSION>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// SSH key redaction strategies
///
/// Controls how SSH keys (public/private) are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show key type only: `<ssh-rsa>`, `<ssh-ed25519>`, `<ecdsa-sha2-nistp256>`
    ShowType,
    /// Show fingerprint if available: `<SSH_KEY-MD5:ab:cd:ef:...>`
    ShowFingerprint,
    /// Token placeholder: `<SSH_KEY>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// SSH fingerprint redaction strategies
///
/// Controls how SSH fingerprints are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshFingerprintRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show type only: `<MD5>` or `<SHA256>`
    ShowType,
    /// Token placeholder: `<SSH_FINGERPRINT>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Generic redaction policy for text scanning
///
/// Simpler interface that maps to domain-specific strategies.
/// Used by `*_in_text()` functions for consistent text redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction
    Skip,
    /// Partial redaction (show prefix, type, etc.)
    Partial,
    /// Complete redaction (use type tokens)
    #[default]
    Complete,
    /// Anonymous redaction (generic `[REDACTED]`)
    Anonymous,
}

impl TextRedactionPolicy {
    /// Convert policy to JWT strategy
    #[must_use]
    pub const fn to_jwt_strategy(self) -> JwtRedactionStrategy {
        match self {
            Self::Skip => JwtRedactionStrategy::Skip,
            Self::Partial => JwtRedactionStrategy::ShowAlgorithm,
            Self::Complete => JwtRedactionStrategy::Token,
            Self::Anonymous => JwtRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to API key strategy
    #[must_use]
    pub const fn to_api_key_strategy(self) -> ApiKeyRedactionStrategy {
        match self {
            Self::Skip => ApiKeyRedactionStrategy::Skip,
            Self::Partial => ApiKeyRedactionStrategy::ShowPrefix,
            Self::Complete => ApiKeyRedactionStrategy::Token,
            Self::Anonymous => ApiKeyRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to session ID strategy
    #[must_use]
    pub const fn to_session_id_strategy(self) -> SessionIdRedactionStrategy {
        match self {
            Self::Skip => SessionIdRedactionStrategy::Skip,
            Self::Partial => SessionIdRedactionStrategy::ShowPrefix,
            Self::Complete => SessionIdRedactionStrategy::Token,
            Self::Anonymous => SessionIdRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to SSH key strategy
    #[must_use]
    pub const fn to_ssh_key_strategy(self) -> SshKeyRedactionStrategy {
        match self {
            Self::Skip => SshKeyRedactionStrategy::Skip,
            Self::Partial => SshKeyRedactionStrategy::ShowType,
            Self::Complete => SshKeyRedactionStrategy::Token,
            Self::Anonymous => SshKeyRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to SSH fingerprint strategy
    #[must_use]
    pub const fn to_ssh_fingerprint_strategy(self) -> SshFingerprintRedactionStrategy {
        match self {
            Self::Skip => SshFingerprintRedactionStrategy::Skip,
            Self::Partial => SshFingerprintRedactionStrategy::ShowType,
            Self::Complete => SshFingerprintRedactionStrategy::Token,
            Self::Anonymous => SshFingerprintRedactionStrategy::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_text_policy_to_jwt_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_jwt_strategy(),
            JwtRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_jwt_strategy(),
            JwtRedactionStrategy::ShowAlgorithm
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_jwt_strategy(),
            JwtRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_jwt_strategy(),
            JwtRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_api_key_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_api_key_strategy(),
            ApiKeyRedactionStrategy::ShowPrefix
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_api_key_strategy(),
            ApiKeyRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_session_id_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_session_id_strategy(),
            SessionIdRedactionStrategy::ShowPrefix
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_session_id_strategy(),
            SessionIdRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_ssh_key_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_ssh_key_strategy(),
            SshKeyRedactionStrategy::ShowType
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_ssh_key_strategy(),
            SshKeyRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_ssh_fingerprint_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_ssh_fingerprint_strategy(),
            SshFingerprintRedactionStrategy::ShowType
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_ssh_fingerprint_strategy(),
            SshFingerprintRedactionStrategy::Token
        );
    }
}
