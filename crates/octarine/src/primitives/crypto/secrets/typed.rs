//! Typed Secrets with NIST-compliant metadata (Layer 1 Primitive)
//!
//! Provides secrets with classification, TTL, and lifecycle metadata
//! following NIST SP 800-57 guidelines for key management.
//!
//! This is the Layer 1 primitive without observability - use
//! `octarine::crypto::secrets::TypedSecret` for the instrumented version.
//!
//! # Features
//!
//! - **Classification levels**: Public, Internal, Confidential, Restricted
//! - **Secret types**: API keys, passwords, tokens, encryption keys, etc.
//! - **TTL support**: Optional expiration with `is_expired()` checks
//! - **Rotation policy**: Track rotation requirements
//! - **Lifecycle states**: Active, Suspended, Compromised, Destroyed
//!
//! # Example
//!
//! ```ignore
//! use crate::primitives::crypto::secrets::{
//!     PrimitiveTypedSecret, SecretType, Classification,
//! };
//! use std::time::Duration;
//!
//! // Create a typed API key with TTL
//! let api_key = PrimitiveTypedSecret::new("sk-12345".to_string())
//!     .with_type(SecretType::ApiKey)
//!     .with_classification(Classification::Confidential)
//!     .with_ttl(Duration::from_secs(86400)); // 24 hours
//!
//! // Check expiration before use
//! if !api_key.is_expired() {
//!     let value = api_key.expose_secret();
//!     // Use the secret...
//! }
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3
#![allow(dead_code)]

use std::fmt;
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use super::{ExposeSecretCore, SecretCore};

// ============================================================================
// Classification (NIST-aligned)
// ============================================================================

/// Data classification levels per NIST guidelines.
///
/// Used to determine handling requirements, access controls,
/// and audit requirements for secrets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Classification {
    /// Public data - no protection required
    Public,
    /// Internal use only - basic protection
    Internal,
    /// Confidential - enhanced protection, limited access
    #[default]
    Confidential,
    /// Restricted - maximum protection, strict access controls
    Restricted,
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "PUBLIC"),
            Self::Internal => write!(f, "INTERNAL"),
            Self::Confidential => write!(f, "CONFIDENTIAL"),
            Self::Restricted => write!(f, "RESTRICTED"),
        }
    }
}

// ============================================================================
// Secret Type
// ============================================================================

/// Types of secrets with semantic meaning.
///
/// Used for auto-detection, appropriate handling, and NIST-recommended
/// rotation policies.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub enum SecretType {
    /// API key for service authentication
    ApiKey,
    /// User or service password
    Password,
    /// Authentication token (JWT, OAuth, session)
    AuthToken,
    /// Refresh token for obtaining new access tokens
    RefreshToken,
    /// Symmetric encryption key (AES, ChaCha20)
    EncryptionKey,
    /// Asymmetric private key (RSA, Ed25519)
    PrivateKey,
    /// Key encryption key (wraps other keys)
    KeyEncryptionKey,
    /// Master key (root of key hierarchy)
    MasterKey,
    /// Database connection credentials
    DatabaseCredential,
    /// TLS/SSL certificate private key
    CertificateKey,
    /// HMAC signing key
    HmacKey,
    /// Webhook secret for signature verification
    WebhookSecret,
    /// SSH private key
    SshKey,
    /// Generic/unclassified secret
    #[default]
    Generic,
}

impl SecretType {
    /// Returns NIST-recommended rotation interval for this secret type.
    ///
    /// Based on NIST SP 800-57 guidelines and industry best practices.
    #[must_use]
    pub fn recommended_rotation_interval(&self) -> Duration {
        match self {
            // Short-lived tokens
            Self::AuthToken => Duration::from_secs(3600), // 1 hour
            Self::RefreshToken => Duration::from_secs(7 * 86400), // 7 days

            // Medium-lived credentials
            Self::Password => Duration::from_secs(90 * 86400), // 90 days
            Self::ApiKey => Duration::from_secs(90 * 86400),   // 90 days
            Self::WebhookSecret => Duration::from_secs(90 * 86400), // 90 days
            Self::DatabaseCredential => Duration::from_secs(90 * 86400), // 90 days

            // Long-lived keys
            Self::EncryptionKey => Duration::from_secs(365 * 86400), // 1 year
            Self::HmacKey => Duration::from_secs(365 * 86400),       // 1 year
            Self::PrivateKey => Duration::from_secs(365 * 86400),    // 1 year
            Self::SshKey => Duration::from_secs(365 * 86400),        // 1 year
            Self::CertificateKey => Duration::from_secs(365 * 86400), // 1 year

            // Very long-lived (requires careful management)
            Self::KeyEncryptionKey => Duration::from_secs(2 * 365 * 86400), // 2 years
            Self::MasterKey => Duration::from_secs(2 * 365 * 86400),        // 2 years

            // Generic - conservative default
            Self::Generic => Duration::from_secs(90 * 86400), // 90 days
        }
    }

    /// Returns the minimum recommended classification for this secret type.
    #[must_use]
    pub fn minimum_classification(&self) -> Classification {
        match self {
            Self::MasterKey | Self::KeyEncryptionKey | Self::PrivateKey => {
                Classification::Restricted
            }
            Self::EncryptionKey
            | Self::DatabaseCredential
            | Self::CertificateKey
            | Self::SshKey => Classification::Confidential,
            Self::ApiKey
            | Self::Password
            | Self::AuthToken
            | Self::RefreshToken
            | Self::HmacKey
            | Self::WebhookSecret => Classification::Confidential,
            Self::Generic => Classification::Internal,
        }
    }
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey => write!(f, "API_KEY"),
            Self::Password => write!(f, "PASSWORD"),
            Self::AuthToken => write!(f, "AUTH_TOKEN"),
            Self::RefreshToken => write!(f, "REFRESH_TOKEN"),
            Self::EncryptionKey => write!(f, "ENCRYPTION_KEY"),
            Self::PrivateKey => write!(f, "PRIVATE_KEY"),
            Self::KeyEncryptionKey => write!(f, "KEY_ENCRYPTION_KEY"),
            Self::MasterKey => write!(f, "MASTER_KEY"),
            Self::DatabaseCredential => write!(f, "DATABASE_CREDENTIAL"),
            Self::CertificateKey => write!(f, "CERTIFICATE_KEY"),
            Self::HmacKey => write!(f, "HMAC_KEY"),
            Self::WebhookSecret => write!(f, "WEBHOOK_SECRET"),
            Self::SshKey => write!(f, "SSH_KEY"),
            Self::Generic => write!(f, "GENERIC"),
        }
    }
}

impl fmt::Debug for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use Display format for consistency in logs and debug output
        write!(f, "{}", self)
    }
}

// ============================================================================
// Lifecycle State
// ============================================================================

/// Secret lifecycle state per NIST SP 800-57.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SecretState {
    /// Active and valid for use
    #[default]
    Active,
    /// Temporarily disabled (can be reactivated)
    Suspended,
    /// Known or suspected compromise - do not use
    Compromised,
    /// Permanently disabled, pending destruction
    Deactivated,
    /// Cryptographically erased
    Destroyed,
}

impl SecretState {
    /// Returns true if the secret can be used for operations.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

// ============================================================================
// Rotation Policy
// ============================================================================

/// Rotation policy for secrets.
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Rotation interval
    pub interval: Duration,
    /// Grace period after expiration (old key still valid)
    pub grace_period: Duration,
    /// Whether to warn before rotation is due
    pub warn_before: Option<Duration>,
}

impl RotationPolicy {
    /// Create a new rotation policy with the given interval.
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            grace_period: Duration::from_secs(86400), // 24 hour default grace
            warn_before: Some(Duration::from_secs(7 * 86400)), // 7 day warning
        }
    }

    /// Set the grace period.
    #[must_use]
    pub fn with_grace_period(mut self, grace: Duration) -> Self {
        self.grace_period = grace;
        self
    }

    /// Set the warning period before rotation.
    #[must_use]
    pub fn with_warning(mut self, warn_before: Duration) -> Self {
        self.warn_before = Some(warn_before);
        self
    }

    /// Disable warning before rotation.
    #[must_use]
    pub fn without_warning(mut self) -> Self {
        self.warn_before = None;
        self
    }
}

// ============================================================================
// PrimitiveTypedSecret
// ============================================================================

/// A secret with NIST-compliant metadata (Layer 1 primitive).
///
/// Wraps a `SecretCore<T>` with classification, type, TTL, and lifecycle
/// information for compliance-grade secret management.
///
/// # Security Features
///
/// - Automatic zeroization on drop (inherited from `SecretCore<T>`)
/// - TTL enforcement via `is_expired()`
/// - State checking via `is_usable()`
/// - Classification-aware handling
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::secrets::{
///     PrimitiveTypedSecret, SecretType, Classification,
/// };
///
/// let secret = PrimitiveTypedSecret::new("my-api-key".to_string())
///     .with_type(SecretType::ApiKey)
///     .with_classification(Classification::Confidential);
///
/// // Safe to log - shows metadata but not value
/// println!("{:?}", secret);
/// // PrimitiveTypedSecret { type: API_KEY, classification: CONFIDENTIAL, ... }
/// ```
pub struct PrimitiveTypedSecret<T: Zeroize> {
    /// The actual secret value
    inner: SecretCore<T>,
    /// Type of secret
    secret_type: SecretType,
    /// Classification level
    classification: Classification,
    /// Lifecycle state
    state: SecretState,
    /// Creation time (monotonic)
    created_at: Instant,
    /// Time-to-live (None = no expiration)
    ttl: Option<Duration>,
    /// Rotation policy
    rotation_policy: Option<RotationPolicy>,
    /// Optional identifier for this secret
    id: Option<String>,
}

impl<T: Zeroize> PrimitiveTypedSecret<T> {
    /// Create a new typed secret with default metadata.
    ///
    /// Defaults to:
    /// - Type: Generic
    /// - Classification: Confidential
    /// - State: Active
    /// - TTL: None (no expiration)
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            inner: SecretCore::new(value),
            secret_type: SecretType::default(),
            classification: Classification::default(),
            state: SecretState::default(),
            created_at: Instant::now(),
            ttl: None,
            rotation_policy: None,
            id: None,
        }
    }

    /// Set the secret type.
    #[must_use]
    pub fn with_type(mut self, secret_type: SecretType) -> Self {
        self.secret_type = secret_type;
        self
    }

    /// Set the classification level.
    #[must_use]
    pub fn with_classification(mut self, classification: Classification) -> Self {
        self.classification = classification;
        self
    }

    /// Set the time-to-live.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the rotation policy.
    #[must_use]
    pub fn with_rotation_policy(mut self, policy: RotationPolicy) -> Self {
        self.rotation_policy = Some(policy);
        self
    }

    /// Set an identifier for this secret.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the lifecycle state.
    pub fn set_state(&mut self, state: SecretState) {
        self.state = state;
    }

    /// Get the secret type.
    #[must_use]
    pub fn secret_type(&self) -> &SecretType {
        &self.secret_type
    }

    /// Get the classification level.
    #[must_use]
    pub fn classification(&self) -> Classification {
        self.classification
    }

    /// Get the lifecycle state.
    #[must_use]
    pub fn state(&self) -> SecretState {
        self.state
    }

    /// Get the optional identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Get the TTL if set.
    #[must_use]
    pub fn ttl(&self) -> Option<Duration> {
        self.ttl
    }

    /// Get the rotation policy if set.
    #[must_use]
    pub fn rotation_policy(&self) -> Option<&RotationPolicy> {
        self.rotation_policy.as_ref()
    }

    /// Get the age of this secret.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Check if the secret has expired based on TTL.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        match self.ttl {
            Some(ttl) => self.created_at.elapsed() > ttl,
            None => false,
        }
    }

    /// Check if rotation is due based on rotation policy.
    #[must_use]
    pub fn is_rotation_due(&self) -> bool {
        match &self.rotation_policy {
            Some(policy) => self.created_at.elapsed() > policy.interval,
            None => false,
        }
    }

    /// Check if rotation warning should be shown.
    #[must_use]
    pub fn is_rotation_warning(&self) -> bool {
        match &self.rotation_policy {
            Some(policy) => {
                if let Some(warn_before) = policy.warn_before {
                    let age = self.created_at.elapsed();
                    let warn_threshold = policy.interval.saturating_sub(warn_before);
                    age > warn_threshold && age <= policy.interval
                } else {
                    false
                }
            }
            None => false,
        }
    }

    /// Check if the secret is usable (active state and not expired).
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.state.is_usable() && !self.is_expired()
    }

    /// Get remaining time before expiration (None if no TTL or already expired).
    #[must_use]
    pub fn remaining_ttl(&self) -> Option<Duration> {
        self.ttl.and_then(|ttl| {
            let elapsed = self.created_at.elapsed();
            // Use checked_sub to avoid potential arithmetic issues
            ttl.checked_sub(elapsed)
        })
    }
}

impl<T: Zeroize> ExposeSecretCore<T> for PrimitiveTypedSecret<T> {
    /// Expose the inner secret value.
    ///
    /// # Security Note
    ///
    /// This does NOT check expiration or state - use `is_usable()` first
    /// if you need to enforce those checks. This matches the behavior of
    /// the base `SecretCore<T>` type.
    fn expose_secret(&self) -> &T {
        self.inner.expose_secret()
    }
}

impl<T: Zeroize> fmt::Debug for PrimitiveTypedSecret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrimitiveTypedSecret")
            .field("type", &self.secret_type)
            .field("classification", &self.classification)
            .field("state", &self.state)
            .field("id", &self.id)
            .field("ttl", &self.ttl)
            .field("age", &self.age())
            .field("expired", &self.is_expired())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl<T: Zeroize + Clone> Clone for PrimitiveTypedSecret<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            secret_type: self.secret_type.clone(),
            classification: self.classification,
            state: self.state,
            created_at: self.created_at,
            ttl: self.ttl,
            rotation_policy: self.rotation_policy.clone(),
            id: self.id.clone(),
        }
    }
}

// ============================================================================
// Type Aliases
// ============================================================================

/// A typed secret string.
pub type TypedSecretString = PrimitiveTypedSecret<String>;

/// Typed secret bytes.
pub type TypedSecretBytes = PrimitiveTypedSecret<Vec<u8>>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_new_typed_secret() {
        let secret = PrimitiveTypedSecret::new("my-secret".to_string());

        assert_eq!(secret.secret_type(), &SecretType::Generic);
        assert_eq!(secret.classification(), Classification::Confidential);
        assert_eq!(secret.state(), SecretState::Active);
        assert!(secret.is_usable());
        assert!(!secret.is_expired());
    }

    #[test]
    fn test_with_type() {
        let secret =
            PrimitiveTypedSecret::new("sk-12345".to_string()).with_type(SecretType::ApiKey);

        assert_eq!(secret.secret_type(), &SecretType::ApiKey);
    }

    #[test]
    fn test_with_classification() {
        let secret = PrimitiveTypedSecret::new("master-key".to_string())
            .with_classification(Classification::Restricted);

        assert_eq!(secret.classification(), Classification::Restricted);
    }

    #[test]
    fn test_ttl_not_expired() {
        let secret =
            PrimitiveTypedSecret::new("temp".to_string()).with_ttl(Duration::from_secs(3600));

        assert!(!secret.is_expired());
        assert!(secret.remaining_ttl().is_some());
    }

    #[test]
    fn test_ttl_expired() {
        let secret =
            PrimitiveTypedSecret::new("temp".to_string()).with_ttl(Duration::from_nanos(1)); // Effectively instant expiration

        std::thread::sleep(Duration::from_millis(1));

        assert!(secret.is_expired());
        assert!(!secret.is_usable());
        assert!(secret.remaining_ttl().is_none());
    }

    #[test]
    fn test_state_transitions() {
        let mut secret = PrimitiveTypedSecret::new("key".to_string());

        assert!(secret.is_usable());

        secret.set_state(SecretState::Suspended);
        assert!(!secret.is_usable());

        secret.set_state(SecretState::Active);
        assert!(secret.is_usable());

        secret.set_state(SecretState::Compromised);
        assert!(!secret.is_usable());
    }

    #[test]
    fn test_rotation_policy() {
        let policy = RotationPolicy::new(Duration::from_secs(86400))
            .with_grace_period(Duration::from_secs(3600))
            .with_warning(Duration::from_secs(7200));

        let secret = PrimitiveTypedSecret::new("key".to_string()).with_rotation_policy(policy);

        assert!(!secret.is_rotation_due());
    }

    #[test]
    fn test_debug_redacts_value() {
        let secret = PrimitiveTypedSecret::new("super-secret-value".to_string())
            .with_type(SecretType::ApiKey);

        let debug = format!("{:?}", secret);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("API_KEY"));
    }

    #[test]
    fn test_expose_secret() {
        let secret = PrimitiveTypedSecret::new("my-value".to_string());

        assert_eq!(secret.expose_secret(), "my-value");
    }

    #[test]
    fn test_with_id() {
        let secret = PrimitiveTypedSecret::new("key".to_string()).with_id("prod-api-key-1");

        assert_eq!(secret.id(), Some("prod-api-key-1"));
    }

    #[test]
    fn test_secret_type_recommended_rotation() {
        assert_eq!(
            SecretType::AuthToken.recommended_rotation_interval(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            SecretType::MasterKey.recommended_rotation_interval(),
            Duration::from_secs(2 * 365 * 86400)
        );
    }

    #[test]
    fn test_secret_type_minimum_classification() {
        assert_eq!(
            SecretType::MasterKey.minimum_classification(),
            Classification::Restricted
        );
        assert_eq!(
            SecretType::ApiKey.minimum_classification(),
            Classification::Confidential
        );
    }

    #[test]
    fn test_classification_ordering() {
        assert!(Classification::Public < Classification::Internal);
        assert!(Classification::Internal < Classification::Confidential);
        assert!(Classification::Confidential < Classification::Restricted);
    }

    #[test]
    fn test_clone() {
        let original = PrimitiveTypedSecret::new("clone-me".to_string())
            .with_type(SecretType::Password)
            .with_classification(Classification::Restricted);

        let cloned = original.clone();

        assert_eq!(original.expose_secret(), cloned.expose_secret());
        assert_eq!(original.secret_type(), cloned.secret_type());
        assert_eq!(original.classification(), cloned.classification());
    }
}
