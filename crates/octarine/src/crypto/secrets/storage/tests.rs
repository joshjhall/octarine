//! Unit tests for `SecretStorage` and `ManagedSecretStorage`.

#![allow(clippy::panic, clippy::expect_used)]

use std::time::Duration;

use super::*;
use crate::primitives::crypto::secrets::{Classification, SecretType};

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
    assert_eq!(
        storage.cleanup_interval(),
        managed::DEFAULT_CLEANUP_INTERVAL
    );
}
