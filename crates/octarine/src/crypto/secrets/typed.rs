//! TypedSecret - Secrets with NIST-compliant metadata and observability
//!
//! Wraps `PrimitiveTypedSecret` with observe instrumentation for audit trails.
//!
//! # Features
//!
//! - All features from `PrimitiveTypedSecret`
//! - Automatic audit logging on secret access
//! - Expiration warnings logged via observe
//! - Rotation due warnings
//! - Security events for compromised secrets
//!
//! # Example
//!
//! ```ignore
//! use octarine::crypto::secrets::{TypedSecret, SecretType, Classification};
//! use std::time::Duration;
//!
//! // Create a typed API key
//! let api_key = TypedSecret::new("sk-12345".to_string())
//!     .with_type(SecretType::ApiKey)
//!     .with_classification(Classification::Confidential)
//!     .with_ttl(Duration::from_secs(86400));
//!
//! // Access is logged via observe
//! if api_key.is_usable() {
//!     let value = api_key.expose_secret_audited("api_call");
//!     // Use the secret...
//! }
//! ```

use std::fmt;
use std::time::Duration;

use zeroize::Zeroize;

use super::ExposeSecret;
use crate::observe;
use crate::primitives::crypto::secrets::{
    Classification, ExposeSecretCore, PrimitiveTypedSecret, RotationPolicy, SecretState, SecretType,
};

/// A typed secret with observe instrumentation.
///
/// Wraps `PrimitiveTypedSecret` to add audit trail logging for
/// compliance-grade secret management.
///
/// # Audit Events
///
/// The following events are logged:
/// - Secret creation (debug level)
/// - Secret access via `expose_secret_audited()` (info level)
/// - Expiration checks when accessing expired secrets (warn level)
/// - State changes (info level)
/// - Rotation due warnings (warn level)
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::{TypedSecret, SecretType};
///
/// let secret = TypedSecret::new("my-api-key".to_string())
///     .with_type(SecretType::ApiKey)
///     .with_id("prod-key-1");
///
/// // Audited access - logs the operation
/// let value = secret.expose_secret_audited("authenticate_request");
/// ```
pub struct TypedSecret<T: Zeroize> {
    inner: PrimitiveTypedSecret<T>,
}

impl<T: Zeroize> TypedSecret<T> {
    /// Create a new typed secret.
    ///
    /// Logs a debug event for secret creation.
    #[must_use]
    pub fn new(value: T) -> Self {
        let inner = PrimitiveTypedSecret::new(value);
        observe::debug(
            "secret_created",
            format!(
                "Created {} secret (classification: {})",
                inner.secret_type(),
                inner.classification()
            ),
        );
        Self { inner }
    }

    /// Set the secret type.
    #[must_use]
    pub fn with_type(mut self, secret_type: SecretType) -> Self {
        self.inner = self.inner.with_type(secret_type);
        self
    }

    /// Set the classification level.
    #[must_use]
    pub fn with_classification(mut self, classification: Classification) -> Self {
        self.inner = self.inner.with_classification(classification);
        self
    }

    /// Set the time-to-live.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.inner = self.inner.with_ttl(ttl);
        self
    }

    /// Set the rotation policy.
    #[must_use]
    pub fn with_rotation_policy(mut self, policy: RotationPolicy) -> Self {
        self.inner = self.inner.with_rotation_policy(policy);
        self
    }

    /// Set an identifier for this secret.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.inner = self.inner.with_id(id);
        self
    }

    /// Set the lifecycle state with audit logging.
    pub fn set_state(&mut self, state: SecretState) {
        let old_state = self.inner.state();
        self.inner.set_state(state);

        let id = self.inner.id().unwrap_or("unknown");
        observe::info(
            "secret_state_changed",
            format!(
                "Secret '{}' state changed: {:?} -> {:?}",
                id, old_state, state
            ),
        );

        // Log security event if compromised
        if state == SecretState::Compromised {
            observe::warn(
                "secret_compromised",
                format!(
                    "Secret '{}' marked as COMPROMISED - immediate rotation required",
                    id
                ),
            );
        }
    }

    /// Get the secret type.
    #[must_use]
    pub fn secret_type(&self) -> &SecretType {
        self.inner.secret_type()
    }

    /// Get the classification level.
    #[must_use]
    pub fn classification(&self) -> Classification {
        self.inner.classification()
    }

    /// Get the lifecycle state.
    #[must_use]
    pub fn state(&self) -> SecretState {
        self.inner.state()
    }

    /// Get the optional identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.inner.id()
    }

    /// Get the TTL if set.
    #[must_use]
    pub fn ttl(&self) -> Option<Duration> {
        self.inner.ttl()
    }

    /// Get the age of this secret.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.inner.age()
    }

    /// Check if the secret has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// Check if rotation is due.
    #[must_use]
    pub fn is_rotation_due(&self) -> bool {
        self.inner.is_rotation_due()
    }

    /// Check if the secret is usable (active and not expired).
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.inner.is_usable()
    }

    /// Get remaining TTL.
    #[must_use]
    pub fn remaining_ttl(&self) -> Option<Duration> {
        self.inner.remaining_ttl()
    }

    /// Expose the secret value with audit logging.
    ///
    /// This is the recommended way to access secrets when you need
    /// an audit trail. The operation name is logged along with
    /// the secret metadata (but NOT the value).
    ///
    /// # Arguments
    ///
    /// * `operation` - Name of the operation accessing the secret
    ///
    /// # Returns
    ///
    /// Reference to the secret value. Returns the value even if
    /// expired or not usable - use `is_usable()` to check first
    /// if you need to enforce those checks.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if secret.is_usable() {
    ///     let value = secret.expose_secret_audited("api_authentication");
    ///     // Use value...
    /// }
    /// ```
    pub fn expose_secret_audited(&self, operation: &str) -> &T {
        let id = self.inner.id().unwrap_or("unknown");

        // Log the access
        observe::info(
            "secret_accessed",
            format!(
                "Secret '{}' ({}) accessed for operation '{}'",
                id,
                self.inner.secret_type(),
                operation
            ),
        );

        // Warn if expired
        if self.inner.is_expired() {
            observe::warn(
                "secret_expired_access",
                format!(
                    "Accessing EXPIRED secret '{}' for operation '{}' - age: {:?}",
                    id,
                    operation,
                    self.inner.age()
                ),
            );
        }

        // Warn if rotation is due
        if self.inner.is_rotation_due() {
            observe::warn(
                "secret_rotation_due",
                format!(
                    "Secret '{}' is due for rotation - age: {:?}",
                    id,
                    self.inner.age()
                ),
            );
        } else if self.inner.is_rotation_warning() {
            observe::info(
                "secret_rotation_warning",
                format!(
                    "Secret '{}' will need rotation soon - age: {:?}",
                    id,
                    self.inner.age()
                ),
            );
        }

        // Warn if not usable
        if !self.inner.state().is_usable() {
            observe::warn(
                "secret_not_usable",
                format!(
                    "Accessing secret '{}' in non-usable state: {:?}",
                    id,
                    self.inner.state()
                ),
            );
        }

        self.inner.expose_secret()
    }

    /// Validate that the secret meets minimum classification requirements.
    ///
    /// Returns true if the secret's classification meets or exceeds
    /// the minimum required for its type.
    #[must_use]
    pub fn is_classification_valid(&self) -> bool {
        self.inner.classification() >= self.inner.secret_type().minimum_classification()
    }

    /// Validate classification and log if insufficient.
    ///
    /// Logs a warning if the classification is below the minimum
    /// recommended for this secret type.
    pub fn validate_classification(&self) {
        if !self.is_classification_valid() {
            let id = self.inner.id().unwrap_or("unknown");
            observe::warn(
                "secret_classification_warning",
                format!(
                    "Secret '{}' has classification {} but {} recommends minimum {}",
                    id,
                    self.inner.classification(),
                    self.inner.secret_type(),
                    self.inner.secret_type().minimum_classification()
                ),
            );
        }
    }
}

// Also implement ExposeSecret for unaudited access (matches primitive behavior)
impl<T: Zeroize> ExposeSecret<T> for TypedSecret<T> {
    /// Expose the secret value WITHOUT audit logging.
    ///
    /// For audited access, use `expose_secret_audited()` instead.
    fn expose_secret(&self) -> &T {
        self.inner.expose_secret()
    }
}

impl<T: Zeroize> fmt::Debug for TypedSecret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedSecret")
            .field("type", &self.inner.secret_type())
            .field("classification", &self.inner.classification())
            .field("state", &self.inner.state())
            .field("id", &self.inner.id())
            .field("ttl", &self.inner.ttl())
            .field("age", &self.inner.age())
            .field("expired", &self.inner.is_expired())
            .field("usable", &self.inner.is_usable())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl<T: Zeroize + Clone> Clone for TypedSecret<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_new_typed_secret() {
        let secret = TypedSecret::new("my-secret".to_string());

        assert_eq!(secret.secret_type(), &SecretType::Generic);
        assert!(secret.is_usable());
    }

    #[test]
    fn test_expose_secret_audited() {
        let secret = TypedSecret::new("my-value".to_string()).with_id("test-secret");

        let value = secret.expose_secret_audited("test_operation");
        assert_eq!(value, "my-value");
    }

    #[test]
    fn test_state_change_logging() {
        let mut secret = TypedSecret::new("key".to_string()).with_id("test-key");

        secret.set_state(SecretState::Suspended);
        assert_eq!(secret.state(), SecretState::Suspended);
    }

    #[test]
    fn test_classification_validation() {
        // API key with correct classification
        let valid = TypedSecret::new("sk-12345".to_string())
            .with_type(SecretType::ApiKey)
            .with_classification(Classification::Confidential);

        assert!(valid.is_classification_valid());

        // Master key with too-low classification
        let invalid = TypedSecret::new("master".to_string())
            .with_type(SecretType::MasterKey)
            .with_classification(Classification::Internal);

        assert!(!invalid.is_classification_valid());
    }

    #[test]
    fn test_debug_redacts_value() {
        let secret = TypedSecret::new("super-secret".to_string()).with_type(SecretType::Password);

        let debug = format!("{:?}", secret);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }
}
