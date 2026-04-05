#![allow(clippy::panic, clippy::expect_used)]

use std::time::Duration;

use octarine::crypto::secrets::{Classification, EncryptedSecretStorage, SecretType};

// =========================================================================
// Basic insert and access (sync)
// =========================================================================

/// Insert → access via with_secret_sync → verify value.
#[test]
fn test_insert_and_access_sync() {
    let storage = EncryptedSecretStorage::new();

    storage
        .insert_sync("api_key", "sk-test-12345")
        .expect("insert");

    let value = storage
        .with_secret_sync("api_key", "test_read", |v| v.to_string())
        .expect("access");

    assert_eq!(value, "sk-test-12345");
}

/// Access nonexistent secret returns error.
#[test]
fn test_access_nonexistent_sync() {
    let storage = EncryptedSecretStorage::new();

    let result = storage.with_secret_sync("missing", "test", |v| v.to_string());
    assert!(result.is_err(), "Nonexistent secret should error");
}

// =========================================================================
// Async insert and access
// =========================================================================

/// Insert typed with classification and access (async).
#[tokio::test]
async fn test_insert_typed_and_access_async() {
    let storage = EncryptedSecretStorage::new();

    storage
        .insert_typed(
            "db_password",
            "hunter2",
            SecretType::DatabaseCredential,
            Classification::Restricted,
            None,
        )
        .await
        .expect("insert typed");

    let value = storage
        .with_secret("db_password", "db_connect", |v| v.to_string())
        .await
        .expect("access");

    assert_eq!(value, "hunter2");
}

// =========================================================================
// TTL expiration
// =========================================================================

/// Insert with short TTL → wait → access fails.
#[tokio::test]
async fn test_ttl_expiration() {
    let storage = EncryptedSecretStorage::new();

    storage
        .insert_typed(
            "temp_token",
            "short-lived-value",
            SecretType::AuthToken,
            Classification::Confidential,
            Some(Duration::from_millis(50)),
        )
        .await
        .expect("insert with TTL");

    // Should be accessible immediately
    let value = storage
        .with_secret("temp_token", "immediate_read", |v| v.to_string())
        .await
        .expect("immediate access");
    assert_eq!(value, "short-lived-value");

    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Should now be expired
    let result = storage
        .with_secret("temp_token", "expired_read", |v| v.to_string())
        .await;
    assert!(result.is_err(), "Expired secret should not be accessible");
}

/// purge_expired removes expired entries.
#[tokio::test]
async fn test_purge_expired() {
    let storage = EncryptedSecretStorage::new();

    storage
        .insert_typed(
            "short",
            "expires-soon",
            SecretType::Generic,
            Classification::Internal,
            Some(Duration::from_millis(10)),
        )
        .await
        .expect("insert short TTL");

    storage
        .insert_typed(
            "long",
            "lives-forever",
            SecretType::Generic,
            Classification::Internal,
            None,
        )
        .await
        .expect("insert no TTL");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let purged = storage.purge_expired().await;
    assert!(purged >= 1, "Should purge at least 1 expired secret");

    // Long-lived secret still accessible
    let value = storage
        .with_secret("long", "read", |v| v.to_string())
        .await
        .expect("long-lived should still work");
    assert_eq!(value, "lives-forever");
}

// =========================================================================
// Remove and contains
// =========================================================================

/// Remove → contains returns false.
#[tokio::test]
async fn test_remove() {
    let storage = EncryptedSecretStorage::new();

    storage.insert("removable", "value").await.expect("insert");

    assert!(storage.contains("removable").await);

    let removed = storage.remove("removable").await;
    assert!(removed, "Should report removal");

    assert!(
        !storage.contains("removable").await,
        "Should no longer contain removed secret"
    );
}

// =========================================================================
// Multiple secrets
// =========================================================================

/// Store multiple secrets, verify each independently.
#[tokio::test]
async fn test_multiple_secrets() {
    let storage = EncryptedSecretStorage::new();

    storage.insert("key1", "value1").await.expect("insert 1");
    storage.insert("key2", "value2").await.expect("insert 2");
    storage.insert("key3", "value3").await.expect("insert 3");

    assert_eq!(storage.len().await, 3);

    let v1 = storage
        .with_secret("key1", "read", |v| v.to_string())
        .await
        .expect("read 1");
    let v2 = storage
        .with_secret("key2", "read", |v| v.to_string())
        .await
        .expect("read 2");
    let v3 = storage
        .with_secret("key3", "read", |v| v.to_string())
        .await
        .expect("read 3");

    assert_eq!(v1, "value1");
    assert_eq!(v2, "value2");
    assert_eq!(v3, "value3");

    let names = storage.names().await;
    assert_eq!(names.len(), 3);
}

/// clear removes all secrets.
#[tokio::test]
async fn test_clear() {
    let storage = EncryptedSecretStorage::new();

    storage.insert("a", "1").await.expect("insert a");
    storage.insert("b", "2").await.expect("insert b");

    storage.clear().await;
    assert!(storage.is_empty().await, "Should be empty after clear");
}

/// Builder configures storage with ID.
#[test]
fn test_builder() {
    let storage = EncryptedSecretStorage::builder()
        .with_id("test-storage")
        .build();

    assert_eq!(storage.id(), Some("test-storage"));
}
