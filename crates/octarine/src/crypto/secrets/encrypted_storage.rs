//! EncryptedSecretStorage - Per-secret encryption with closure-based access
//!
//! Provides secure storage where each secret is individually encrypted using
//! ChaCha20-Poly1305 via `SecureBuffer`. Secrets are only decrypted within
//! closure scope, minimizing plaintext exposure.
//!
//! # Security Model
//!
//! - Each secret has its own ephemeral encryption key
//! - Plaintext only exists within closure scope
//! - Keys and plaintext are zeroized on drop
//! - Encryption protects against memory dumps and cold boot attacks
//!
//! # Example
//!
//! ```ignore
//! use octarine::crypto::secrets::EncryptedSecretStorage;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let storage = EncryptedSecretStorage::builder()
//!         .with_id("app-secrets")
//!         .with_cleanup_interval(Duration::from_secs(60))
//!         .build();
//!
//!     // Start background cleanup
//!     storage.start_cleanup().await;
//!
//!     // Insert encrypts automatically
//!     storage.insert("api_key", "sk-12345").await?;
//!
//!     // Access via closure - plaintext only exists in closure scope
//!     let result = storage.with_secret("api_key", "api_call", |value| {
//!         // Use the decrypted value
//!         println!("Key length: {}", value.len());
//!         Ok::<_, std::io::Error>(())
//!     }).await?;
//!
//!     storage.stop_cleanup().await;
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;

use crate::observe;
use crate::observe::metrics::{MetricName, increment, timer};
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::secrets::{Classification, SecretType};

use super::buffer::SecureBuffer;

// ============================================================================
// Metric Names (validated at startup)
// ============================================================================

// Validated at compile time: these metric names are known-good static strings.
// Using `unwrap_or_else` with a fallback provides compile-time validation
// that the pattern is correct while avoiding expect() lints.

/// Metric name for storage creation count
fn metric_storage_created() -> MetricName {
    // SAFETY: Static string known to be valid at compile time
    #[allow(clippy::expect_used)]
    MetricName::new("secrets.storage.created").expect("static metric name")
}

/// Metric name for insert operations
fn metric_insert_count() -> MetricName {
    #[allow(clippy::expect_used)]
    MetricName::new("secrets.insert_count").expect("static metric name")
}

/// Metric name for access operations
fn metric_access_count() -> MetricName {
    #[allow(clippy::expect_used)]
    MetricName::new("secrets.access_count").expect("static metric name")
}

/// Metric name for expired secrets purged
fn metric_expired_count() -> MetricName {
    #[allow(clippy::expect_used)]
    MetricName::new("secrets.expired_count").expect("static metric name")
}

/// Metric name for encryption timing
fn metric_encryption_time() -> &'static str {
    "secrets.encryption_time_ms"
}

/// Metric name for decryption timing
fn metric_decryption_time() -> &'static str {
    "secrets.decryption_time_ms"
}

// ============================================================================
// Types
// ============================================================================

/// Metadata for an encrypted secret.
#[derive(Debug, Clone)]
struct SecretMetadata {
    /// Type of secret
    secret_type: SecretType,
    /// Classification level
    classification: Classification,
    /// Creation time
    created_at: Instant,
    /// Time-to-live
    ttl: Option<Duration>,
}

impl SecretMetadata {
    fn is_expired(&self) -> bool {
        match self.ttl {
            Some(ttl) => self.created_at.elapsed() > ttl,
            None => false,
        }
    }
}

/// An encrypted secret with metadata.
struct EncryptedSecret {
    /// Encrypted value
    buffer: SecureBuffer,
    /// Metadata (not encrypted - needed for expiration checks)
    metadata: SecretMetadata,
}

/// Error type for encrypted storage operations.
#[derive(Debug, thiserror::Error)]
pub enum EncryptedStorageError {
    /// Secret not found
    #[error("secret '{0}' not found")]
    NotFound(String),

    /// Secret has expired
    #[error("secret '{0}' has expired")]
    Expired(String),

    /// Encryption/decryption failed
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

impl From<EncryptedStorageError> for crate::observe::Problem {
    fn from(err: EncryptedStorageError) -> Self {
        match err {
            EncryptedStorageError::NotFound(name) => Self::not_found(format!("secret '{name}'")),
            EncryptedStorageError::Expired(name) => {
                Self::validation(format!("secret '{name}' has expired"))
            }
            EncryptedStorageError::Crypto(e) => e.into(),
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Default cleanup interval (60 seconds)
const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Configuration for encrypted secret storage.
#[derive(Debug, Clone)]
pub struct EncryptedStorageConfig {
    /// Storage identifier for audit logs
    pub storage_id: Option<String>,
    /// Interval between cleanup runs
    pub cleanup_interval: Duration,
}

impl Default for EncryptedStorageConfig {
    fn default() -> Self {
        Self {
            storage_id: None,
            cleanup_interval: DEFAULT_CLEANUP_INTERVAL,
        }
    }
}

// ============================================================================
// EncryptedSecretStorage
// ============================================================================

/// Encrypted secret storage with per-secret encryption and closure-based access.
///
/// Each secret is encrypted using ChaCha20-Poly1305 with its own ephemeral key.
/// Secrets are only decrypted within closure scope via `with_secret()`, ensuring
/// plaintext exposure is minimized.
///
/// # Features
///
/// - **Per-secret encryption**: Each secret has its own key
/// - **Closure-based access**: Plaintext only exists in closure scope
/// - **TTL support**: Secrets can expire automatically
/// - **Background cleanup**: Expired secrets are purged periodically
/// - **Audit logging**: All operations logged via observe
/// - **Metrics**: Access counts, encryption timing tracked
///
/// # Example
///
/// ```ignore
/// let storage = EncryptedSecretStorage::builder()
///     .with_id("my-secrets")
///     .build();
///
/// // Insert (encrypts automatically)
/// storage.insert("api_key", "sk-12345").await?;
///
/// // Access via closure
/// storage.with_secret("api_key", "authenticate", |key| {
///     // key is decrypted here, zeroized when closure returns
///     make_request(key)
/// }).await?;
/// ```
pub struct EncryptedSecretStorage {
    /// Encrypted secrets
    secrets: Arc<RwLock<HashMap<String, EncryptedSecret>>>,
    /// Configuration
    config: EncryptedStorageConfig,
    /// Shutdown signal for cleanup task
    shutdown: Arc<Notify>,
    /// Handle to the cleanup task
    cleanup_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl EncryptedSecretStorage {
    /// Create a new encrypted storage with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(EncryptedStorageConfig::default())
    }

    /// Create a new encrypted storage with configuration.
    #[must_use]
    pub fn with_config(config: EncryptedStorageConfig) -> Self {
        observe::debug(
            "encrypted_storage_created",
            format!(
                "Created EncryptedSecretStorage (id: {:?}, cleanup_interval: {:?})",
                config.storage_id, config.cleanup_interval
            ),
        );

        // Record metric
        increment(metric_storage_created());

        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
            config,
            shutdown: Arc::new(Notify::new()),
            cleanup_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a builder for configuring encrypted storage.
    #[must_use]
    pub fn builder() -> EncryptedStorageBuilder {
        EncryptedStorageBuilder::new()
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

    // ========================================================================
    // Background Cleanup
    // ========================================================================

    /// Start the background cleanup task.
    pub async fn start_cleanup(&self) {
        let mut handle_guard = self.cleanup_handle.write().await;

        if handle_guard.is_some() {
            observe::debug("encrypted_storage_cleanup", "Cleanup task already running");
            return;
        }

        let secrets = Arc::clone(&self.secrets);
        let shutdown = Arc::clone(&self.shutdown);
        let interval = self.config.cleanup_interval;
        let storage_id = self.config.storage_id.clone();

        observe::info(
            "encrypted_storage_cleanup_start",
            format!(
                "Starting background cleanup for encrypted storage {:?}",
                storage_id
            ),
        );

        let handle = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        let mut secrets_guard = secrets.write().await;
                        let before = secrets_guard.len();

                        secrets_guard.retain(|name, secret| {
                            if secret.metadata.is_expired() {
                                observe::debug(
                                    "encrypted_storage_expired",
                                    format!("Purging expired secret '{}'", name),
                                );
                                false
                            } else {
                                true
                            }
                        });

                        let purged = before.saturating_sub(secrets_guard.len());
                        if purged > 0 {
                            observe::info(
                                "encrypted_storage_cleanup_run",
                                format!(
                                    "Purged {} expired secrets from {:?}",
                                    purged, storage_id
                                ),
                            );
                            for _ in 0..purged {
                                increment(metric_expired_count());
                            }
                        }
                    }
                    _ = shutdown.notified() => {
                        observe::info(
                            "encrypted_storage_cleanup_stop",
                            format!("Background cleanup stopped for {:?}", storage_id),
                        );
                        break;
                    }
                }
            }
        });

        *handle_guard = Some(handle);
    }

    /// Stop the background cleanup task.
    pub async fn stop_cleanup(&self) {
        self.shutdown.notify_one();

        let mut handle_guard = self.cleanup_handle.write().await;
        if let Some(handle) = handle_guard.take() {
            let _ = handle.await;
        }
    }

    /// Check if cleanup is running.
    pub async fn is_cleanup_running(&self) -> bool {
        self.cleanup_handle.read().await.is_some()
    }

    // ========================================================================
    // Storage Operations
    // ========================================================================

    /// Insert a secret with default settings.
    ///
    /// The secret is immediately encrypted with a unique ephemeral key.
    pub async fn insert(
        &self,
        name: impl Into<String>,
        value: impl AsRef<str>,
    ) -> Result<(), EncryptedStorageError> {
        self.insert_typed(
            name,
            value,
            SecretType::Generic,
            Classification::Confidential,
            None,
        )
        .await
    }

    /// Insert a secret with full type information.
    pub async fn insert_typed(
        &self,
        name: impl Into<String>,
        value: impl AsRef<str>,
        secret_type: SecretType,
        classification: Classification,
        ttl: Option<Duration>,
    ) -> Result<(), EncryptedStorageError> {
        let name = name.into();
        let value = value.as_ref();
        let storage_id = self.config.storage_id.as_deref().unwrap_or("default");

        // Encrypt the value (with timing)
        let _timer = timer(metric_encryption_time());
        let buffer = SecureBuffer::new(value.as_bytes().to_vec())?;
        drop(_timer); // Explicitly drop to record timing

        let metadata = SecretMetadata {
            secret_type: secret_type.clone(),
            classification,
            created_at: Instant::now(),
            ttl,
        };

        let encrypted = EncryptedSecret { buffer, metadata };

        let mut secrets = self.secrets.write().await;
        secrets.insert(name.clone(), encrypted);

        observe::info(
            "encrypted_storage_insert",
            format!(
                "Secret '{}' stored in '{}' (type: {}, classification: {}, encrypted: {}bytes)",
                name,
                storage_id,
                secret_type,
                classification,
                value.len()
            ),
        );

        increment(metric_insert_count());

        Ok(())
    }

    /// Access a secret via closure (audited).
    ///
    /// The secret is decrypted only within the closure scope. The plaintext
    /// is zeroized when the closure returns.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the secret
    /// * `operation` - Description of why the secret is being accessed (for audit)
    /// * `f` - Closure that receives the decrypted value as `&str`
    ///
    /// # Returns
    ///
    /// The return value of the closure, or an error if the secret doesn't exist,
    /// is expired, or decryption fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = storage.with_secret("api_key", "make_request", |key| {
    ///     api_client.authenticate(key)
    /// }).await?;
    /// ```
    pub async fn with_secret<F, R>(
        &self,
        name: &str,
        operation: &str,
        f: F,
    ) -> Result<R, EncryptedStorageError>
    where
        F: FnOnce(&str) -> R,
    {
        let storage_id = self.config.storage_id.as_deref().unwrap_or("default");
        let secrets = self.secrets.read().await;

        let encrypted = secrets.get(name).ok_or_else(|| {
            observe::warn(
                "encrypted_storage_not_found",
                format!(
                    "Secret '{}' not found in '{}' for operation '{}'",
                    name, storage_id, operation
                ),
            );
            EncryptedStorageError::NotFound(name.to_string())
        })?;

        // Check expiration
        if encrypted.metadata.is_expired() {
            observe::warn(
                "encrypted_storage_expired",
                format!(
                    "Secret '{}' in '{}' has expired (operation: '{}')",
                    name, storage_id, operation
                ),
            );
            return Err(EncryptedStorageError::Expired(name.to_string()));
        }

        observe::info(
            "encrypted_storage_access",
            format!(
                "Secret '{}' ({}, {}) accessed for operation '{}' in '{}'",
                name,
                encrypted.metadata.secret_type,
                encrypted.metadata.classification,
                operation,
                storage_id
            ),
        );

        increment(metric_access_count());

        // Decrypt and call closure (with timing)
        let _timer = timer(metric_decryption_time());
        let result = encrypted.buffer.with_decrypted(|bytes| {
            // Convert to string - if not valid UTF-8, this will be lossy
            let value = std::str::from_utf8(bytes).unwrap_or_else(|_| {
                observe::warn(
                    "encrypted_storage_utf8",
                    format!("Secret '{}' contains invalid UTF-8", name),
                );
                ""
            });
            f(value)
        })?;

        Ok(result)
    }

    /// Access a secret via closure with mutable decrypted buffer.
    ///
    /// Similar to `with_secret`, but provides `&[u8]` instead of `&str`,
    /// useful for binary secrets.
    pub async fn with_secret_bytes<F, R>(
        &self,
        name: &str,
        operation: &str,
        f: F,
    ) -> Result<R, EncryptedStorageError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        let storage_id = self.config.storage_id.as_deref().unwrap_or("default");
        let secrets = self.secrets.read().await;

        let encrypted = secrets
            .get(name)
            .ok_or_else(|| EncryptedStorageError::NotFound(name.to_string()))?;

        if encrypted.metadata.is_expired() {
            return Err(EncryptedStorageError::Expired(name.to_string()));
        }

        observe::info(
            "encrypted_storage_access",
            format!(
                "Secret '{}' ({}) accessed (bytes) for operation '{}' in '{}'",
                name, encrypted.metadata.secret_type, operation, storage_id
            ),
        );

        increment(metric_access_count());

        let result = encrypted.buffer.with_decrypted(f)?;

        Ok(result)
    }

    /// Check if a secret exists (without decrypting).
    pub async fn contains(&self, name: &str) -> bool {
        let secrets = self.secrets.read().await;
        secrets.get(name).is_some_and(|s| !s.metadata.is_expired())
    }

    /// Remove a secret from storage.
    pub async fn remove(&self, name: &str) -> bool {
        let storage_id = self.config.storage_id.as_deref().unwrap_or("default");
        let mut secrets = self.secrets.write().await;

        if secrets.remove(name).is_some() {
            observe::info(
                "encrypted_storage_remove",
                format!("Secret '{}' removed from '{}'", name, storage_id),
            );
            true
        } else {
            false
        }
    }

    /// Get the number of secrets (including expired).
    pub async fn len(&self) -> usize {
        self.secrets.read().await.len()
    }

    /// Check if storage is empty.
    pub async fn is_empty(&self) -> bool {
        self.secrets.read().await.is_empty()
    }

    /// Get all secret names.
    pub async fn names(&self) -> Vec<String> {
        self.secrets.read().await.keys().cloned().collect()
    }

    /// Manually purge expired secrets.
    pub async fn purge_expired(&self) -> usize {
        let storage_id = self.config.storage_id.as_deref().unwrap_or("default");
        let mut secrets = self.secrets.write().await;

        let before = secrets.len();
        secrets.retain(|_, secret| !secret.metadata.is_expired());
        let purged = before.saturating_sub(secrets.len());

        if purged > 0 {
            observe::info(
                "encrypted_storage_purge",
                format!("Purged {} expired secrets from '{}'", purged, storage_id),
            );
            for _ in 0..purged {
                increment(metric_expired_count());
            }
        }

        purged
    }

    /// Clear all secrets.
    pub async fn clear(&self) {
        let storage_id = self.config.storage_id.as_deref().unwrap_or("default");
        let mut secrets = self.secrets.write().await;
        let count = secrets.len();
        secrets.clear();

        observe::info(
            "encrypted_storage_clear",
            format!("Cleared {} secrets from '{}'", count, storage_id),
        );
    }

    // ========================================================================
    // Sync Variants
    // ========================================================================

    /// Insert a secret (sync, blocking).
    ///
    /// **Warning**: This WILL block the current thread.
    pub fn insert_sync(
        &self,
        name: impl Into<String>,
        value: impl AsRef<str>,
    ) -> Result<(), EncryptedStorageError> {
        let name = name.into();
        let value = value.as_ref();
        let storage_id = self.config.storage_id.as_deref().unwrap_or("default");

        let buffer = SecureBuffer::new(value.as_bytes().to_vec())?;

        let metadata = SecretMetadata {
            secret_type: SecretType::Generic,
            classification: Classification::Confidential,
            created_at: Instant::now(),
            ttl: None,
        };

        let encrypted = EncryptedSecret { buffer, metadata };

        let mut secrets = self.secrets.blocking_write();
        secrets.insert(name.clone(), encrypted);

        observe::info(
            "encrypted_storage_insert",
            format!("Secret '{}' stored (sync) in '{}'", name, storage_id),
        );

        increment(metric_insert_count());

        Ok(())
    }

    /// Access a secret via closure (sync, blocking).
    ///
    /// **Warning**: This WILL block the current thread.
    pub fn with_secret_sync<F, R>(
        &self,
        name: &str,
        operation: &str,
        f: F,
    ) -> Result<R, EncryptedStorageError>
    where
        F: FnOnce(&str) -> R,
    {
        let storage_id = self.config.storage_id.as_deref().unwrap_or("default");
        let secrets = self.secrets.blocking_read();

        let encrypted = secrets
            .get(name)
            .ok_or_else(|| EncryptedStorageError::NotFound(name.to_string()))?;

        if encrypted.metadata.is_expired() {
            return Err(EncryptedStorageError::Expired(name.to_string()));
        }

        observe::info(
            "encrypted_storage_access",
            format!(
                "Secret '{}' accessed (sync) for '{}' in '{}'",
                name, operation, storage_id
            ),
        );

        increment(metric_access_count());

        let result = encrypted.buffer.with_decrypted(|bytes| {
            let value = std::str::from_utf8(bytes).unwrap_or("");
            f(value)
        })?;

        Ok(result)
    }
}

impl Default for EncryptedSecretStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EncryptedSecretStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecretStorage")
            .field("id", &self.config.storage_id)
            .field("cleanup_interval", &self.config.cleanup_interval)
            .field("secrets", &"[ENCRYPTED]")
            .finish()
    }
}

impl Drop for EncryptedSecretStorage {
    fn drop(&mut self) {
        self.shutdown.notify_one();

        if let Some(id) = &self.config.storage_id {
            observe::debug(
                "encrypted_storage_dropped",
                format!("EncryptedSecretStorage '{}' dropped", id),
            );
        }
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for `EncryptedSecretStorage`.
#[derive(Debug, Default)]
pub struct EncryptedStorageBuilder {
    config: EncryptedStorageConfig,
}

impl EncryptedStorageBuilder {
    /// Create a new builder.
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

    /// Build the encrypted storage.
    #[must_use]
    pub fn build(self) -> EncryptedSecretStorage {
        EncryptedSecretStorage::with_config(self.config)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new() {
        let storage = EncryptedSecretStorage::new();
        assert!(storage.is_empty().await);
        assert!(storage.id().is_none());
    }

    #[tokio::test]
    async fn test_builder() {
        let storage = EncryptedSecretStorage::builder()
            .with_id("test-encrypted")
            .with_cleanup_interval(Duration::from_secs(30))
            .build();

        assert_eq!(storage.id(), Some("test-encrypted"));
        assert_eq!(storage.cleanup_interval(), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_insert_and_access() {
        let storage = EncryptedSecretStorage::new();

        storage.insert("api_key", "sk-12345").await.expect("insert");

        assert!(storage.contains("api_key").await);
        assert_eq!(storage.len().await, 1);

        // Access via closure
        let result = storage
            .with_secret("api_key", "test", |value| {
                assert_eq!(value, "sk-12345");
                value.len()
            })
            .await
            .expect("with_secret");

        assert_eq!(result, 8);
    }

    #[tokio::test]
    async fn test_insert_typed() {
        let storage = EncryptedSecretStorage::builder()
            .with_id("typed-test")
            .build();

        storage
            .insert_typed(
                "password",
                "hunter2",
                SecretType::Password,
                Classification::Restricted,
                None,
            )
            .await
            .expect("insert_typed");

        let result = storage
            .with_secret("password", "auth", |value| value.to_string())
            .await
            .expect("with_secret");

        assert_eq!(result, "hunter2");
    }

    #[tokio::test]
    async fn test_not_found() {
        let storage = EncryptedSecretStorage::new();

        let result = storage.with_secret("missing", "test", |_| ()).await;

        assert!(matches!(result, Err(EncryptedStorageError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_expired() {
        let storage = EncryptedSecretStorage::new();

        storage
            .insert_typed(
                "ephemeral",
                "temp",
                SecretType::AuthToken,
                Classification::Confidential,
                Some(Duration::from_nanos(1)), // Instant expiration
            )
            .await
            .expect("insert_typed");

        tokio::time::sleep(Duration::from_millis(1)).await;

        let result = storage.with_secret("ephemeral", "test", |_| ()).await;

        assert!(matches!(result, Err(EncryptedStorageError::Expired(_))));
    }

    #[tokio::test]
    async fn test_with_secret_bytes() {
        let storage = EncryptedSecretStorage::new();

        storage.insert("binary", "hello").await.expect("insert");

        let result = storage
            .with_secret_bytes("binary", "test", |bytes| bytes.len())
            .await
            .expect("with_secret_bytes");

        assert_eq!(result, 5);
    }

    #[tokio::test]
    async fn test_remove() {
        let storage = EncryptedSecretStorage::new();

        storage.insert("key", "value").await.expect("insert");
        assert!(storage.contains("key").await);

        assert!(storage.remove("key").await);
        assert!(!storage.contains("key").await);
        assert!(!storage.remove("key").await);
    }

    #[tokio::test]
    async fn test_clear() {
        let storage = EncryptedSecretStorage::new();

        storage.insert("key1", "value1").await.expect("insert");
        storage.insert("key2", "value2").await.expect("insert");

        storage.clear().await;

        assert!(storage.is_empty().await);
    }

    #[tokio::test]
    async fn test_names() {
        let storage = EncryptedSecretStorage::new();

        storage.insert("key1", "value1").await.expect("insert");
        storage.insert("key2", "value2").await.expect("insert");

        let names = storage.names().await;
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"key1".to_string()));
        assert!(names.contains(&"key2".to_string()));
    }

    #[tokio::test]
    async fn test_purge_expired() {
        let storage = EncryptedSecretStorage::new();

        // Add expiring secret
        storage
            .insert_typed(
                "expired",
                "temp",
                SecretType::AuthToken,
                Classification::Confidential,
                Some(Duration::from_nanos(1)),
            )
            .await
            .expect("insert_typed");

        // Add permanent secret
        storage.insert("permanent", "value").await.expect("insert");

        tokio::time::sleep(Duration::from_millis(1)).await;

        let purged = storage.purge_expired().await;
        assert_eq!(purged, 1);
        assert_eq!(storage.len().await, 1);
        assert!(storage.contains("permanent").await);
    }

    #[tokio::test]
    async fn test_background_cleanup() {
        let storage = EncryptedSecretStorage::builder()
            .with_id("bg-test")
            .with_cleanup_interval(Duration::from_millis(10))
            .build();

        // Add expiring secret
        storage
            .insert_typed(
                "ephemeral",
                "temp",
                SecretType::AuthToken,
                Classification::Confidential,
                Some(Duration::from_nanos(1)),
            )
            .await
            .expect("insert_typed");

        storage.insert("permanent", "value").await.expect("insert");

        storage.start_cleanup().await;
        assert!(storage.is_cleanup_running().await);

        // Poll until cleanup runs (with timeout) - more reliable than fixed sleep
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(5);
        while storage.len().await > 1 && start.elapsed() < timeout {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(storage.len().await, 1);
        assert!(storage.contains("permanent").await);

        storage.stop_cleanup().await;
        assert!(!storage.is_cleanup_running().await);
    }

    #[test]
    fn test_sync_variants() {
        let storage = EncryptedSecretStorage::new();

        storage.insert_sync("key", "value").expect("insert_sync");

        let result = storage
            .with_secret_sync("key", "test", |v| v.to_string())
            .expect("with_secret_sync");

        assert_eq!(result, "value");
    }

    #[tokio::test]
    async fn test_debug_shows_encrypted() {
        let storage = EncryptedSecretStorage::builder()
            .with_id("debug-test")
            .build();

        storage
            .insert("secret", "super-secret")
            .await
            .expect("insert");

        let debug = format!("{:?}", storage);
        assert!(debug.contains("[ENCRYPTED]"));
        assert!(debug.contains("debug-test"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn test_default() {
        let storage = EncryptedSecretStorage::default();
        assert!(storage.id().is_none());
    }

    #[test]
    fn test_error_display() {
        let not_found = EncryptedStorageError::NotFound("key".to_string());
        assert_eq!(not_found.to_string(), "secret 'key' not found");

        let expired = EncryptedStorageError::Expired("key".to_string());
        assert_eq!(expired.to_string(), "secret 'key' has expired");
    }
}
