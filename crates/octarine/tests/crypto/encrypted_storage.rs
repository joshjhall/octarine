#![allow(clippy::panic, clippy::expect_used)]

use std::time::{Duration, Instant};

use octarine::crypto::secrets::{Classification, EncryptedSecretStorage, SecretType};
use tokio::time::timeout;

/// Per-test executor timeout. Prevents a stalled runtime or held lock from
/// hanging CI; longest legitimate internal deadline in this file is ~5 s.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time the polling loops in TTL tests will wait for a secret to
/// expire before giving up. Generous enough to absorb coverage-instrumented
/// and nightly CI runs, where a 50-100 ms scheduling slip can otherwise
/// flake fixed-sleep assertions (see `octarine-test-resilience` skill).
const EXPIRY_POLL_DEADLINE: Duration = Duration::from_secs(5);
const EXPIRY_POLL_INTERVAL: Duration = Duration::from_millis(25);

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
    timeout(TEST_TIMEOUT, async {
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
    })
    .await
    .expect("test timed out after 30s");
}

// =========================================================================
// TTL expiration
// =========================================================================

/// Insert with TTL → read immediately → wait → access fails.
///
/// TTL is sized generously (500 ms) so the immediate read has slack even
/// under coverage-instrumented / nightly CI; the expiration check polls
/// rather than sleeping a fixed amount (Rule 2 of `octarine-test-resilience`).
#[tokio::test]
async fn test_ttl_expiration() {
    timeout(TEST_TIMEOUT, async {
        let storage = EncryptedSecretStorage::new();

        storage
            .insert_typed(
                "temp_token",
                "short-lived-value",
                SecretType::AuthToken,
                Classification::Confidential,
                Some(Duration::from_millis(500)),
            )
            .await
            .expect("insert with TTL");

        // Should be accessible immediately
        let value = storage
            .with_secret("temp_token", "immediate_read", |v| v.to_string())
            .await
            .expect("immediate access");
        assert_eq!(value, "short-lived-value");

        // Poll until the secret expires (or give up after EXPIRY_POLL_DEADLINE).
        let deadline = Instant::now() + EXPIRY_POLL_DEADLINE;
        loop {
            let result = storage
                .with_secret("temp_token", "expired_read", |v| v.to_string())
                .await;
            if result.is_err() {
                break;
            }
            if Instant::now() > deadline {
                panic!("Secret did not expire within {EXPIRY_POLL_DEADLINE:?}");
            }
            tokio::time::sleep(EXPIRY_POLL_INTERVAL).await;
        }
    })
    .await
    .expect("test timed out after 30s");
}

/// purge_expired removes expired entries.
///
/// TTL is sized generously (500 ms) and expiration is polled rather than
/// asserted after a fixed sleep — same pattern as `test_ttl_expiration`.
#[tokio::test]
async fn test_purge_expired() {
    timeout(TEST_TIMEOUT, async {
        let storage = EncryptedSecretStorage::new();

        storage
            .insert_typed(
                "short",
                "expires-soon",
                SecretType::Generic,
                Classification::Internal,
                Some(Duration::from_millis(500)),
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

        // Poll until purge_expired actually removes the short-lived entry.
        let deadline = Instant::now() + EXPIRY_POLL_DEADLINE;
        let purged = loop {
            let n = storage.purge_expired().await;
            if n >= 1 {
                break n;
            }
            if Instant::now() > deadline {
                panic!("Short-TTL secret did not expire within {EXPIRY_POLL_DEADLINE:?}");
            }
            tokio::time::sleep(EXPIRY_POLL_INTERVAL).await;
        };
        assert!(purged >= 1, "Should purge at least 1 expired secret");

        // Long-lived secret still accessible
        let value = storage
            .with_secret("long", "read", |v| v.to_string())
            .await
            .expect("long-lived should still work");
        assert_eq!(value, "lives-forever");
    })
    .await
    .expect("test timed out after 30s");
}

// =========================================================================
// Remove and contains
// =========================================================================

/// Remove → contains returns false.
#[tokio::test]
async fn test_remove() {
    timeout(TEST_TIMEOUT, async {
        let storage = EncryptedSecretStorage::new();

        storage.insert("removable", "value").await.expect("insert");

        assert!(storage.contains("removable").await);

        let removed = storage.remove("removable").await;
        assert!(removed, "Should report removal");

        assert!(
            !storage.contains("removable").await,
            "Should no longer contain removed secret"
        );
    })
    .await
    .expect("test timed out after 30s");
}

// =========================================================================
// Multiple secrets
// =========================================================================

/// Store multiple secrets, verify each independently.
#[tokio::test]
async fn test_multiple_secrets() {
    timeout(TEST_TIMEOUT, async {
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
    })
    .await
    .expect("test timed out after 30s");
}

/// clear removes all secrets.
#[tokio::test]
async fn test_clear() {
    timeout(TEST_TIMEOUT, async {
        let storage = EncryptedSecretStorage::new();

        storage.insert("a", "1").await.expect("insert a");
        storage.insert("b", "2").await.expect("insert b");

        storage.clear().await;
        assert!(storage.is_empty().await, "Should be empty after clear");
    })
    .await
    .expect("test timed out after 30s");
}

/// Builder configures storage with ID.
#[test]
fn test_builder() {
    let storage = EncryptedSecretStorage::builder()
        .with_id("test-storage")
        .build();

    assert_eq!(storage.id(), Some("test-storage"));
}
