//! `SecretStorage` — basic named-secret storage with audit trails
//!
//! Sync API for storing typed secrets by name. Used directly for thread-local
//! storage or wrapped by `ManagedSecretStorage` (see `managed`) for async
//! access with background cleanup.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use crate::crypto::secrets::{ExposeSecret, TypedSecret};
use crate::observe;
use crate::primitives::crypto::secrets::{Classification, SecretType};

/// Secure storage for named secrets with audit trails.
///
/// Stores `TypedSecret` values by name with full observe instrumentation
/// for compliance-grade audit logging.
///
/// # Audit Events
///
/// - `secret_storage_insert` - Secret added to storage
/// - `secret_storage_get` - Secret accessed (via `get_audited`)
/// - `secret_storage_remove` - Secret removed from storage
/// - `secret_storage_expired` - Attempted access to expired secret
/// - `secret_storage_not_found` - Attempted access to missing secret
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::SecretStorage;
///
/// let mut storage = SecretStorage::new();
///
/// // Simple insert (auto-detected as Generic)
/// storage.insert("my_secret", "value");
///
/// // Get with audit logging
/// let value = storage.get_audited("my_secret", "operation_name");
/// ```
pub struct SecretStorage {
    pub(super) secrets: HashMap<String, TypedSecret<String>>,
    /// Storage identifier for audit logs
    pub(super) storage_id: Option<String>,
}

impl SecretStorage {
    /// Create a new empty secret storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            storage_id: None,
        }
    }

    /// Create a new secret storage with an identifier.
    ///
    /// The identifier is included in audit logs for easier tracking.
    #[must_use]
    pub fn with_id(id: impl Into<String>) -> Self {
        let id = id.into();
        observe::debug(
            "secret_storage_created",
            format!("Secret storage '{}' created", id),
        );
        Self {
            secrets: HashMap::new(),
            storage_id: Some(id),
        }
    }

    /// Get the storage identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.storage_id.as_deref()
    }

    /// Insert a secret with default settings.
    ///
    /// The secret type is set to Generic and classification to Confidential.
    /// For more control, use `insert_typed()`.
    pub fn insert(&mut self, name: impl Into<String>, value: String) {
        let name = name.into();
        self.insert_typed(
            &name,
            value,
            SecretType::Generic,
            Classification::Confidential,
            None,
        );
    }

    /// Insert a secret with full type information.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the secret
    /// * `value` - The secret value
    /// * `secret_type` - Type of secret (ApiKey, Password, etc.)
    /// * `classification` - Data classification level
    /// * `ttl` - Optional time-to-live
    ///
    /// # Example
    ///
    /// ```ignore
    /// storage.insert_typed(
    ///     "db_password",
    ///     "hunter2".to_string(),
    ///     SecretType::Password,
    ///     Classification::Restricted,
    ///     Some(Duration::from_secs(90 * 86400)), // 90 days
    /// );
    /// ```
    pub fn insert_typed(
        &mut self,
        name: &str,
        value: String,
        secret_type: SecretType,
        classification: Classification,
        ttl: Option<Duration>,
    ) {
        let storage_id = self.storage_id.as_deref().unwrap_or("default");

        let mut typed = TypedSecret::new(value)
            .with_type(secret_type.clone())
            .with_classification(classification)
            .with_id(format!("{}:{}", storage_id, name));

        if let Some(ttl) = ttl {
            typed = typed.with_ttl(ttl);
        }

        observe::info(
            "secret_storage_insert",
            format!(
                "Secret '{}' stored in '{}' (type: {}, classification: {})",
                name, storage_id, secret_type, classification
            ),
        );

        self.secrets.insert(name.to_string(), typed);
    }

    /// Get a secret WITHOUT audit logging.
    ///
    /// Returns None if the secret doesn't exist or is expired.
    /// For audited access, use `get_audited()`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).and_then(|secret| {
            if secret.is_usable() {
                Some(secret.expose_secret().as_str())
            } else {
                None
            }
        })
    }

    /// Get a secret WITH audit logging.
    ///
    /// Logs the access operation for compliance audit trails.
    /// Returns None if the secret doesn't exist or is expired.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the secret to retrieve
    /// * `operation` - Description of why the secret is being accessed
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(api_key) = storage.get_audited("api_key", "send_request") {
    ///     // Use the key...
    /// }
    /// ```
    pub fn get_audited(&self, name: &str, operation: &str) -> Option<&str> {
        let storage_id = self.storage_id.as_deref().unwrap_or("default");

        match self.secrets.get(name) {
            Some(secret) => {
                if secret.is_expired() {
                    observe::warn(
                        "secret_storage_expired",
                        format!(
                            "Attempted access to expired secret '{}' in '{}' for operation '{}'",
                            name, storage_id, operation
                        ),
                    );
                    return None;
                }

                if !secret.is_usable() {
                    observe::warn(
                        "secret_storage_not_usable",
                        format!(
                            "Secret '{}' in '{}' is not usable (state: {:?})",
                            name,
                            storage_id,
                            secret.state()
                        ),
                    );
                    return None;
                }

                // Use the audited access method on TypedSecret
                Some(secret.expose_secret_audited(operation))
            }
            None => {
                observe::warn(
                    "secret_storage_not_found",
                    format!(
                        "Secret '{}' not found in '{}' for operation '{}'",
                        name, storage_id, operation
                    ),
                );
                None
            }
        }
    }

    /// Check if a secret exists (without accessing it).
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.secrets.contains_key(name)
    }

    /// Check if a secret exists and is usable.
    #[must_use]
    pub fn is_usable(&self, name: &str) -> bool {
        self.secrets
            .get(name)
            .is_some_and(|secret| secret.is_usable())
    }

    /// Remove a secret from storage.
    ///
    /// Logs the removal for audit trail.
    pub fn remove(&mut self, name: &str) -> bool {
        let storage_id = self.storage_id.as_deref().unwrap_or("default");

        if self.secrets.remove(name).is_some() {
            observe::info(
                "secret_storage_remove",
                format!("Secret '{}' removed from '{}'", name, storage_id),
            );
            true
        } else {
            false
        }
    }

    /// Get the number of secrets stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Check if storage is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Get all secret names (not values).
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.secrets.keys().map(String::as_str).collect()
    }

    /// Remove all expired secrets.
    ///
    /// Returns the count of removed secrets.
    pub fn purge_expired(&mut self) -> usize {
        let storage_id = self.storage_id.as_deref().unwrap_or("default");

        let expired: Vec<String> = self
            .secrets
            .iter()
            .filter(|(_, secret)| secret.is_expired())
            .map(|(name, _)| name.clone())
            .collect();

        let count = expired.len();

        for name in expired {
            self.secrets.remove(&name);
        }

        if count > 0 {
            observe::info(
                "secret_storage_purge",
                format!("Purged {} expired secrets from '{}'", count, storage_id),
            );
        }

        count
    }

    /// Clear all secrets from storage.
    pub fn clear(&mut self) {
        let storage_id = self.storage_id.as_deref().unwrap_or("default");
        let count = self.secrets.len();

        // Zeroize each secret before removing
        self.secrets.clear();

        observe::info(
            "secret_storage_clear",
            format!("Cleared {} secrets from '{}'", count, storage_id),
        );
    }
}

impl Default for SecretStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecretStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStorage")
            .field("id", &self.storage_id)
            .field("count", &self.secrets.len())
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SecretStorage {
    fn drop(&mut self) {
        // Secrets are zeroized via their TypedSecret Drop impls
        // Just log the cleanup
        if let Some(id) = &self.storage_id {
            observe::debug(
                "secret_storage_dropped",
                format!(
                    "Secret storage '{}' dropped, {} secrets zeroized",
                    id,
                    self.secrets.len()
                ),
            );
        }
    }
}
