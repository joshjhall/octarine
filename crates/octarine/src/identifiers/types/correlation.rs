//! Public correlation types for credential pair detection.
//!
//! These are the public API types wrapping the internal primitives types.

use super::core::{DetectionConfidence, IdentifierMatch};

// Primitives aliases for From conversions
use crate::primitives::identifiers::CorrelationConfig as PrimConfig;
use crate::primitives::identifiers::CorrelationMatch as PrimMatch;
use crate::primitives::identifiers::CredentialPairType as PrimPairType;

/// Types of known credential pairs that can be detected through proximity correlation.
///
/// Each variant represents a specific combination of identifiers that, when found
/// near each other, strongly indicate a complete credential set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialPairType {
    /// AWS access key (`AKIA...`) paired with a secret key (40 base64 chars)
    AwsKeyPair,
    /// OAuth `client_id` paired with `client_secret`
    OAuthClientPair,
    /// Username or email paired with a password
    UsernamePasswordPair,
    /// Access token paired with a refresh token
    TokenPair,
    /// Public key paired with a private or secret key
    KeyPair,
    /// Twilio Account SID (`AC...`) paired with an Auth Token (32 hex)
    TwilioPair,
    /// Azure `client_id` + `client_secret` + `tenant_id` triple
    AzureServicePrincipal,
}

impl From<PrimPairType> for CredentialPairType {
    fn from(p: PrimPairType) -> Self {
        match p {
            PrimPairType::AwsKeyPair => Self::AwsKeyPair,
            PrimPairType::OAuthClientPair => Self::OAuthClientPair,
            PrimPairType::UsernamePasswordPair => Self::UsernamePasswordPair,
            PrimPairType::TokenPair => Self::TokenPair,
            PrimPairType::KeyPair => Self::KeyPair,
            PrimPairType::TwilioPair => Self::TwilioPair,
            PrimPairType::AzureServicePrincipal => Self::AzureServicePrincipal,
        }
    }
}

impl From<CredentialPairType> for PrimPairType {
    fn from(p: CredentialPairType) -> Self {
        match p {
            CredentialPairType::AwsKeyPair => Self::AwsKeyPair,
            CredentialPairType::OAuthClientPair => Self::OAuthClientPair,
            CredentialPairType::UsernamePasswordPair => Self::UsernamePasswordPair,
            CredentialPairType::TokenPair => Self::TokenPair,
            CredentialPairType::KeyPair => Self::KeyPair,
            CredentialPairType::TwilioPair => Self::TwilioPair,
            CredentialPairType::AzureServicePrincipal => Self::AzureServicePrincipal,
        }
    }
}

/// A matched credential pair found through proximity correlation.
#[derive(Debug, Clone)]
pub struct CorrelationMatch {
    /// The type of credential pair detected
    pub pair_type: CredentialPairType,
    /// The first identifier in the pair (earlier position in text)
    pub primary: IdentifierMatch,
    /// The second identifier in the pair (later position in text)
    pub secondary: IdentifierMatch,
    /// Confidence level — always `High` for correlated pairs
    pub confidence: DetectionConfidence,
    /// Character distance between the end of primary and start of secondary
    pub proximity_chars: usize,
}

impl From<PrimMatch> for CorrelationMatch {
    fn from(m: PrimMatch) -> Self {
        Self {
            pair_type: m.pair_type.into(),
            primary: m.primary.into(),
            secondary: m.secondary.into(),
            confidence: m.confidence.into(),
            proximity_chars: m.proximity_chars,
        }
    }
}

/// Configuration for credential pair correlation detection.
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Maximum number of lines between two identifiers to consider them a pair.
    /// Default: 5
    pub max_proximity_lines: usize,
    /// Maximum character distance between two identifiers to consider them a pair.
    /// Default: 500
    pub max_proximity_chars: usize,
    /// Which credential pair types to detect. Default: all types.
    pub enabled_pairs: Vec<CredentialPairType>,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            max_proximity_lines: 5,
            max_proximity_chars: 500,
            enabled_pairs: vec![
                CredentialPairType::AwsKeyPair,
                CredentialPairType::OAuthClientPair,
                CredentialPairType::UsernamePasswordPair,
                CredentialPairType::TokenPair,
                CredentialPairType::KeyPair,
                CredentialPairType::TwilioPair,
                CredentialPairType::AzureServicePrincipal,
            ],
        }
    }
}

impl From<CorrelationConfig> for PrimConfig {
    fn from(c: CorrelationConfig) -> Self {
        Self {
            max_proximity_lines: c.max_proximity_lines,
            max_proximity_chars: c.max_proximity_chars,
            enabled_pairs: c.enabled_pairs.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<PrimConfig> for CorrelationConfig {
    fn from(c: PrimConfig) -> Self {
        Self {
            max_proximity_lines: c.max_proximity_lines,
            max_proximity_chars: c.max_proximity_chars,
            enabled_pairs: c.enabled_pairs.into_iter().map(Into::into).collect(),
        }
    }
}
