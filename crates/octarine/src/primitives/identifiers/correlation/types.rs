use super::super::types::{DetectionConfidence, IdentifierMatch};

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

/// A matched credential pair found through proximity correlation.
///
/// When two identifiers are found within a configured proximity window and
/// match a known pair pattern, a `CorrelationMatch` is produced with `High`
/// confidence — the co-occurrence dramatically reduces false positive rates.
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

/// Configuration for credential pair correlation detection.
///
/// Controls the proximity window and which pair types to scan for.
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
