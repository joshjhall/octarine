//! `ManagedSecretStorage` — async wrapper with background cleanup
//!
//! Provides:
//! - `ManagedStorageConfig`: storage ID + cleanup interval
//! - `ManagedSecretStorage`: `Arc<RwLock<SecretStorage>>` plus a tokio cleanup task
//! - `ManagedStorageBuilder`: fluent builder for the above

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;

use crate::observe;
use crate::primitives::crypto::secrets::{Classification, SecretType};

use super::basic::SecretStorage;

/// Default cleanup interval (60 seconds)
pub(super) const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

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
/// Pre-existing example - ignored at compile until adapted.
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
    pub(super) config: ManagedStorageConfig,
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
