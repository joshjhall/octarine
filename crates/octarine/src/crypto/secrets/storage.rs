//! SecretStorage - Named secret storage with audit trails
//!
//! Provides secure storage for named secrets with:
//! - NIST-compliant metadata (classification, TTL)
//! - Full audit trail for all operations via observe
//! - Automatic expiration checking
//! - Memory zeroization on drop
//! - Optional background cleanup of expired secrets
//!
//! # Types
//!
//! - [`SecretStorage`] - Basic storage (manual cleanup via `purge_expired()`)
//! - [`ManagedSecretStorage`] - Storage with automatic background cleanup
//!
//! # Example
//!
//! ```ignore
//! use octarine::crypto::secrets::{SecretStorage, SecretType, Classification};
//! use std::time::Duration;
//!
//! let mut storage = SecretStorage::new();
//!
//! // Store a secret with metadata
//! storage.insert_typed(
//!     "api_key",
//!     "sk-12345".to_string(),
//!     SecretType::ApiKey,
//!     Classification::Confidential,
//!     Some(Duration::from_secs(86400)),
//! );
//!
//! // Access with audit logging
//! if let Some(value) = storage.get_audited("api_key", "authenticate") {
//!     // Use the value...
//! }
//! ```
//!
//! # Managed Storage with Background Cleanup
//!
//! ```ignore
//! use octarine::crypto::secrets::ManagedSecretStorage;
//! use std::time::Duration;
//!
//! // Create storage with automatic cleanup every 60 seconds
//! let storage = ManagedSecretStorage::new()
//!     .with_id("app-secrets")
//!     .with_cleanup_interval(Duration::from_secs(60))
//!     .build();
//!
//! // Start background cleanup task
//! storage.start_cleanup().await;
//!
//! // Use storage...
//! storage.insert("temp_token", "abc123".to_string()).await;
//!
//! // Stop cleanup on shutdown
//! storage.stop_cleanup().await;
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;

use crate::observe;
use crate::primitives::crypto::secrets::{Classification, SecretType};

use super::{ExposeSecret, TypedSecret};

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
    secrets: HashMap<String, TypedSecret<String>>,
    /// Storage identifier for audit logs
    storage_id: Option<String>,
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

// ============================================================================
// ManagedSecretStorage - Async storage with background cleanup
// ============================================================================

/// Default cleanup interval (60 seconds)
const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Configuration for managed secret storage.
#[derive(Debug, Clone)]
pub struct ManagedStorageConfig {
    /// Storage identifier for audit logs
    pub storage_id: Option<String>,
    /// Interval between cleanup runs
    pub cleanup_interval: Duration,
}

impl Default for ManagedStorageConfig {
    fn default() -> Self {
        Self {
            storage_id: None,
            cleanup_interval: DEFAULT_CLEANUP_INTERVAL,
        }
    }
}

/// Managed secret storage with automatic background cleanup.
///
/// Wraps `SecretStorage` with:
/// - Async-safe access via `Arc<RwLock<>>`
/// - Background task for automatic expired secret cleanup
/// - Graceful shutdown support
///
/// # Background Cleanup
///
/// When `start_cleanup()` is called, a background tokio task periodically
/// removes expired secrets. The task can be stopped with `stop_cleanup()`
/// or by dropping the storage.
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::ManagedSecretStorage;
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///     // Create with builder pattern
///     let storage = ManagedSecretStorage::builder()
///         .with_id("my-secrets")
///         .with_cleanup_interval(Duration::from_secs(30))
///         .build();
///
///     // Start background cleanup
///     storage.start_cleanup().await;
///
///     // Insert secrets (async)
///     storage.insert("api_key", "sk-12345".to_string()).await;
///
///     // Get secrets (async)
///     if let Some(key) = storage.get("api_key").await {
///         println!("Got key");
///     }
///
///     // Stop cleanup before shutdown
///     storage.stop_cleanup().await;
/// }
/// ```
pub struct ManagedSecretStorage {
    /// Inner storage protected by async RwLock
    inner: Arc<RwLock<SecretStorage>>,
    /// Configuration
    config: ManagedStorageConfig,
    /// Shutdown signal for cleanup task
    shutdown: Arc<Notify>,
    /// Handle to the cleanup task (if running)
    cleanup_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl ManagedSecretStorage {
    /// Create a new managed storage with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ManagedStorageConfig::default())
    }

    /// Create a new managed storage with configuration.
    #[must_use]
    pub fn with_config(config: ManagedStorageConfig) -> Self {
        let inner_storage = match &config.storage_id {
            Some(id) => SecretStorage::with_id(id),
            None => SecretStorage::new(),
        };

        observe::debug(
            "managed_storage_created",
            format!(
                "Created ManagedSecretStorage (id: {:?}, cleanup_interval: {:?})",
                config.storage_id, config.cleanup_interval
            ),
        );

        Self {
            inner: Arc::new(RwLock::new(inner_storage)),
            config,
            shutdown: Arc::new(Notify::new()),
            cleanup_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a builder for configuring managed storage.
    #[must_use]
    pub fn builder() -> ManagedStorageBuilder {
        ManagedStorageBuilder::new()
    }

    /// Get the storage identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.config.storage_id.as_deref()
    }

    /// Get the cleanup interval.
    #[must_use]
    pub fn cleanup_interval(&self) -> Duration {
        self.config.cleanup_interval
    }

    /// Start the background cleanup task.
    ///
    /// The task runs until `stop_cleanup()` is called or the storage is dropped.
    /// Calling this multiple times is safe - subsequent calls are no-ops if
    /// cleanup is already running.
    pub async fn start_cleanup(&self) {
        let mut handle_guard = self.cleanup_handle.write().await;

        // Already running?
        if handle_guard.is_some() {
            observe::debug(
                "managed_storage_cleanup",
                "Cleanup task already running, ignoring start request",
            );
            return;
        }

        let inner = Arc::clone(&self.inner);
        let shutdown = Arc::clone(&self.shutdown);
        let interval = self.config.cleanup_interval;
        let storage_id = self.config.storage_id.clone();

        observe::info(
            "managed_storage_cleanup_start",
            format!(
                "Starting background cleanup for storage {:?} (interval: {:?})",
                storage_id, interval
            ),
        );

        let handle = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        let mut storage = inner.write().await;
                        let purged = storage.purge_expired();
                        if purged > 0 {
                            observe::debug(
                                "managed_storage_cleanup_run",
                                format!(
                                    "Background cleanup purged {} expired secrets from {:?}",
                                    purged, storage_id
                                ),
                            );
                        }
                    }
                    _ = shutdown.notified() => {
                        observe::info(
                            "managed_storage_cleanup_stop",
                            format!("Background cleanup stopped for storage {:?}", storage_id),
                        );
                        break;
                    }
                }
            }
        });

        *handle_guard = Some(handle);
    }

    /// Stop the background cleanup task.
    ///
    /// This is called automatically on drop, but can be called manually
    /// for graceful shutdown.
    pub async fn stop_cleanup(&self) {
        // Signal shutdown
        self.shutdown.notify_one();

        // Wait for task to finish
        let mut handle_guard = self.cleanup_handle.write().await;
        if let Some(handle) = handle_guard.take() {
            let _ = handle.await;
        }
    }

    /// Check if the cleanup task is running.
    pub async fn is_cleanup_running(&self) -> bool {
        let handle_guard = self.cleanup_handle.read().await;
        handle_guard.is_some()
    }

    // ========================================================================
    // Async storage operations
    // ========================================================================

    /// Insert a secret with default settings (async).
    pub async fn insert(&self, name: impl Into<String>, value: String) {
        let mut storage = self.inner.write().await;
        storage.insert(name, value);
    }

    /// Insert a secret with full type information (async).
    pub async fn insert_typed(
        &self,
        name: &str,
        value: String,
        secret_type: SecretType,
        classification: Classification,
        ttl: Option<Duration>,
    ) {
        let mut storage = self.inner.write().await;
        storage.insert_typed(name, value, secret_type, classification, ttl);
    }

    /// Get a secret WITHOUT audit logging (async).
    ///
    /// Returns None if the secret doesn't exist or is expired.
    pub async fn get(&self, name: &str) -> Option<String> {
        let storage = self.inner.read().await;
        storage.get(name).map(String::from)
    }

    /// Get a secret WITH audit logging (async).
    ///
    /// Logs the access operation for compliance audit trails.
    pub async fn get_audited(&self, name: &str, operation: &str) -> Option<String> {
        let storage = self.inner.read().await;
        storage.get_audited(name, operation).map(String::from)
    }

    /// Check if a secret exists (async).
    pub async fn contains(&self, name: &str) -> bool {
        let storage = self.inner.read().await;
        storage.contains(name)
    }

    /// Check if a secret exists and is usable (async).
    pub async fn is_usable(&self, name: &str) -> bool {
        let storage = self.inner.read().await;
        storage.is_usable(name)
    }

    /// Remove a secret from storage (async).
    pub async fn remove(&self, name: &str) -> bool {
        let mut storage = self.inner.write().await;
        storage.remove(name)
    }

    /// Get the number of secrets stored (async).
    pub async fn len(&self) -> usize {
        let storage = self.inner.read().await;
        storage.len()
    }

    /// Check if storage is empty (async).
    pub async fn is_empty(&self) -> bool {
        let storage = self.inner.read().await;
        storage.is_empty()
    }

    /// Get all secret names (async).
    pub async fn names(&self) -> Vec<String> {
        let storage = self.inner.read().await;
        storage.names().into_iter().map(String::from).collect()
    }

    /// Manually purge expired secrets (async).
    ///
    /// This is called automatically by the background task if running.
    pub async fn purge_expired(&self) -> usize {
        let mut storage = self.inner.write().await;
        storage.purge_expired()
    }

    /// Clear all secrets from storage (async).
    pub async fn clear(&self) {
        let mut storage = self.inner.write().await;
        storage.clear();
    }

    // ========================================================================
    // Sync variants
    // ========================================================================

    /// Insert a secret (sync, blocking).
    ///
    /// **Warning**: This WILL block the current thread.
    pub fn insert_sync(&self, name: impl Into<String>, value: String) {
        let mut storage = self.inner.blocking_write();
        storage.insert(name, value);
    }

    /// Get a secret WITHOUT audit logging (sync, blocking).
    ///
    /// **Warning**: This WILL block the current thread.
    pub fn get_sync(&self, name: &str) -> Option<String> {
        let storage = self.inner.blocking_read();
        storage.get(name).map(String::from)
    }

    /// Get a secret WITH audit logging (sync, blocking).
    ///
    /// **Warning**: This WILL block the current thread.
    pub fn get_audited_sync(&self, name: &str, operation: &str) -> Option<String> {
        let storage = self.inner.blocking_read();
        storage.get_audited(name, operation).map(String::from)
    }
}

impl Default for ManagedSecretStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ManagedSecretStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedSecretStorage")
            .field("id", &self.config.storage_id)
            .field("cleanup_interval", &self.config.cleanup_interval)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ManagedSecretStorage {
    fn drop(&mut self) {
        // Signal shutdown to cleanup task
        self.shutdown.notify_one();

        if let Some(id) = &self.config.storage_id {
            observe::debug(
                "managed_storage_dropped",
                format!("ManagedSecretStorage '{}' dropped", id),
            );
        }
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for `ManagedSecretStorage`.
#[derive(Debug, Default)]
pub struct ManagedStorageBuilder {
    config: ManagedStorageConfig,
}

impl ManagedStorageBuilder {
    /// Create a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the storage identifier.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.config.storage_id = Some(id.into());
        self
    }

    /// Set the cleanup interval.
    #[must_use]
    pub fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.config.cleanup_interval = interval;
        self
    }

    /// Build the managed storage.
    #[must_use]
    pub fn build(self) -> ManagedSecretStorage {
        ManagedSecretStorage::with_config(self.config)
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
    fn test_new_storage() {
        let storage = SecretStorage::new();
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);
        assert!(storage.id().is_none());
    }

    #[test]
    fn test_with_id() {
        let storage = SecretStorage::with_id("test-storage");
        assert_eq!(storage.id(), Some("test-storage"));
    }

    #[test]
    fn test_insert_and_get() {
        let mut storage = SecretStorage::new();
        storage.insert("key1", "value1".to_string());

        assert!(storage.contains("key1"));
        assert_eq!(storage.get("key1"), Some("value1"));
        assert_eq!(storage.len(), 1);
    }

    #[test]
    fn test_insert_typed() {
        let mut storage = SecretStorage::new();
        storage.insert_typed(
            "api_key",
            "sk-12345".to_string(),
            SecretType::ApiKey,
            Classification::Confidential,
            None,
        );

        assert!(storage.contains("api_key"));
        assert_eq!(storage.get("api_key"), Some("sk-12345"));
    }

    #[test]
    fn test_get_missing() {
        let storage = SecretStorage::new();
        assert_eq!(storage.get("nonexistent"), None);
    }

    #[test]
    fn test_get_audited() {
        let mut storage = SecretStorage::with_id("test");
        storage.insert("secret", "value".to_string());

        let result = storage.get_audited("secret", "test_operation");
        assert_eq!(result, Some("value"));
    }

    #[test]
    fn test_get_audited_missing() {
        let storage = SecretStorage::with_id("test");
        let result = storage.get_audited("missing", "test_operation");
        assert_eq!(result, None);
    }

    #[test]
    fn test_remove() {
        let mut storage = SecretStorage::new();
        storage.insert("key", "value".to_string());

        assert!(storage.remove("key"));
        assert!(!storage.contains("key"));
        assert!(!storage.remove("key")); // Already removed
    }

    #[test]
    fn test_clear() {
        let mut storage = SecretStorage::new();
        storage.insert("key1", "value1".to_string());
        storage.insert("key2", "value2".to_string());

        storage.clear();

        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);
    }

    #[test]
    fn test_names() {
        let mut storage = SecretStorage::new();
        storage.insert("key1", "value1".to_string());
        storage.insert("key2", "value2".to_string());

        let names = storage.names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"key1"));
        assert!(names.contains(&"key2"));
    }

    #[test]
    fn test_is_usable() {
        let mut storage = SecretStorage::new();
        storage.insert("active", "value".to_string());

        assert!(storage.is_usable("active"));
        assert!(!storage.is_usable("missing"));
    }

    #[test]
    fn test_ttl_expiration() {
        let mut storage = SecretStorage::new();
        storage.insert_typed(
            "ephemeral",
            "temp".to_string(),
            SecretType::AuthToken,
            Classification::Confidential,
            Some(Duration::from_nanos(1)), // Instant expiration
        );

        std::thread::sleep(Duration::from_millis(1));

        // Should be expired now
        assert!(!storage.is_usable("ephemeral"));
        assert_eq!(storage.get("ephemeral"), None);
    }

    #[test]
    fn test_purge_expired() {
        let mut storage = SecretStorage::new();

        // Add an instantly-expiring secret
        storage.insert_typed(
            "expired",
            "temp".to_string(),
            SecretType::AuthToken,
            Classification::Confidential,
            Some(Duration::from_nanos(1)),
        );

        // Add a non-expiring secret
        storage.insert("permanent", "value".to_string());

        std::thread::sleep(Duration::from_millis(1));

        let purged = storage.purge_expired();
        assert_eq!(purged, 1);
        assert_eq!(storage.len(), 1);
        assert!(storage.contains("permanent"));
        assert!(!storage.contains("expired"));
    }

    #[test]
    fn test_debug_redacts() {
        let mut storage = SecretStorage::with_id("debug-test");
        storage.insert("secret", "super-secret-value".to_string());

        let debug = format!("{:?}", storage);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("debug-test"));
    }

    #[test]
    fn test_default() {
        let storage = SecretStorage::default();
        assert!(storage.is_empty());
    }

    // ========================================================================
    // ManagedSecretStorage tests
    // ========================================================================

    #[tokio::test]
    async fn test_managed_new() {
        let storage = ManagedSecretStorage::new();
        assert!(storage.is_empty().await);
        assert!(storage.id().is_none());
    }

    #[tokio::test]
    async fn test_managed_builder() {
        let storage = ManagedSecretStorage::builder()
            .with_id("test-managed")
            .with_cleanup_interval(Duration::from_secs(30))
            .build();

        assert_eq!(storage.id(), Some("test-managed"));
        assert_eq!(storage.cleanup_interval(), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_managed_insert_and_get() {
        let storage = ManagedSecretStorage::new();
        storage.insert("key", "value".to_string()).await;

        assert!(storage.contains("key").await);
        assert_eq!(storage.get("key").await, Some("value".to_string()));
        assert_eq!(storage.len().await, 1);
    }

    #[tokio::test]
    async fn test_managed_insert_typed() {
        let storage = ManagedSecretStorage::new();
        storage
            .insert_typed(
                "api_key",
                "sk-12345".to_string(),
                SecretType::ApiKey,
                Classification::Confidential,
                None,
            )
            .await;

        assert!(storage.contains("api_key").await);
        assert_eq!(storage.get("api_key").await, Some("sk-12345".to_string()));
    }

    #[tokio::test]
    async fn test_managed_get_audited() {
        let storage = ManagedSecretStorage::builder()
            .with_id("audit-test")
            .build();

        storage.insert("secret", "value".to_string()).await;

        let result = storage.get_audited("secret", "test_op").await;
        assert_eq!(result, Some("value".to_string()));
    }

    #[tokio::test]
    async fn test_managed_remove() {
        let storage = ManagedSecretStorage::new();
        storage.insert("key", "value".to_string()).await;

        assert!(storage.remove("key").await);
        assert!(!storage.contains("key").await);
    }

    #[tokio::test]
    async fn test_managed_clear() {
        let storage = ManagedSecretStorage::new();
        storage.insert("key1", "value1".to_string()).await;
        storage.insert("key2", "value2".to_string()).await;

        storage.clear().await;

        assert!(storage.is_empty().await);
    }

    #[tokio::test]
    async fn test_managed_names() {
        let storage = ManagedSecretStorage::new();
        storage.insert("key1", "value1".to_string()).await;
        storage.insert("key2", "value2".to_string()).await;

        let names = storage.names().await;
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"key1".to_string()));
        assert!(names.contains(&"key2".to_string()));
    }

    #[tokio::test]
    async fn test_managed_purge_expired() {
        let storage = ManagedSecretStorage::new();

        // Add an instantly-expiring secret
        storage
            .insert_typed(
                "expired",
                "temp".to_string(),
                SecretType::AuthToken,
                Classification::Confidential,
                Some(Duration::from_nanos(1)),
            )
            .await;

        // Add a non-expiring secret
        storage.insert("permanent", "value".to_string()).await;

        tokio::time::sleep(Duration::from_millis(1)).await;

        let purged = storage.purge_expired().await;
        assert_eq!(purged, 1);
        assert_eq!(storage.len().await, 1);
        assert!(storage.contains("permanent").await);
        assert!(!storage.contains("expired").await);
    }

    #[tokio::test]
    async fn test_managed_cleanup_start_stop() {
        let storage = ManagedSecretStorage::builder()
            .with_id("cleanup-test")
            .with_cleanup_interval(Duration::from_millis(10))
            .build();

        assert!(!storage.is_cleanup_running().await);

        storage.start_cleanup().await;
        assert!(storage.is_cleanup_running().await);

        // Starting again should be a no-op
        storage.start_cleanup().await;
        assert!(storage.is_cleanup_running().await);

        storage.stop_cleanup().await;
        assert!(!storage.is_cleanup_running().await);
    }

    #[tokio::test]
    async fn test_managed_background_cleanup() {
        let storage = ManagedSecretStorage::builder()
            .with_id("bg-cleanup-test")
            .with_cleanup_interval(Duration::from_millis(10))
            .build();

        // Add an instantly-expiring secret
        storage
            .insert_typed(
                "ephemeral",
                "temp".to_string(),
                SecretType::AuthToken,
                Classification::Confidential,
                Some(Duration::from_nanos(1)),
            )
            .await;

        // Add a permanent secret
        storage.insert("permanent", "value".to_string()).await;

        assert_eq!(storage.len().await, 2);

        // Start background cleanup
        storage.start_cleanup().await;

        // Poll until cleanup runs. Under CI coverage instrumentation, timing can
        // be unpredictable, so we poll with a generous timeout rather than a
        // fixed sleep.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while storage.len().await > 1 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Expired secret should have been purged
        assert_eq!(storage.len().await, 1);
        assert!(storage.contains("permanent").await);
        assert!(!storage.contains("ephemeral").await);

        storage.stop_cleanup().await;
    }

    #[test]
    fn test_managed_sync_variants() {
        // Sync variants must be tested outside a tokio runtime
        // because blocking_read/write cannot be called from within one
        let storage = ManagedSecretStorage::new();

        storage.insert_sync("key", "value".to_string());

        let value = storage.get_sync("key");
        assert_eq!(value, Some("value".to_string()));

        let audited = storage.get_audited_sync("key", "test");
        assert_eq!(audited, Some("value".to_string()));
    }

    #[tokio::test]
    async fn test_managed_debug_redacts() {
        let storage = ManagedSecretStorage::builder()
            .with_id("debug-test")
            .build();

        storage.insert("secret", "super-secret".to_string()).await;

        let debug = format!("{:?}", storage);
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("debug-test"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn test_managed_default() {
        let storage = ManagedSecretStorage::default();
        assert!(storage.id().is_none());
        assert_eq!(storage.cleanup_interval(), DEFAULT_CLEANUP_INTERVAL);
    }
}
