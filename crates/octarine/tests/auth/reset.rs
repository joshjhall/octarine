#![allow(clippy::panic, clippy::expect_used)]

use std::time::{Duration, Instant};

use octarine::auth::{MemoryResetStore, ResetConfig, ResetManager};

fn make_manager() -> ResetManager<MemoryResetStore> {
    let store = MemoryResetStore::new();
    ResetManager::with_store(store)
}

fn make_manager_with_ttl(ttl: Duration) -> ResetManager<MemoryResetStore> {
    let store = MemoryResetStore::new();
    let config = ResetConfig::builder().token_lifetime(ttl).build();
    ResetManager::new(store, config)
}

/// Request reset → validate → consume → second consume fails.
#[test]
fn test_reset_token_single_use() {
    let manager = make_manager();
    let user = "alice@example.com";

    let token = manager.request_reset(user).expect("request reset");
    let token_value = token.value().to_string();

    // Validate without consuming
    let validated_user = manager.validate(&token_value).expect("validate");
    assert_eq!(validated_user, user);

    // Consume the token
    manager
        .validate_and_consume(&token_value, user)
        .expect("consume");

    // Second consume should fail
    assert!(
        manager.validate_and_consume(&token_value, user).is_err(),
        "Token should not be consumable twice"
    );
}

/// Token expires after configured lifetime.
#[test]
fn test_token_expiration() {
    let manager = make_manager_with_ttl(Duration::from_millis(10));
    let user = "bob@example.com";

    let token = manager.request_reset(user).expect("request reset");
    let token_value = token.value().to_string();

    // Poll for expiration rather than sleeping a fixed margin: the TTL stays
    // at 10ms, but a loaded runner may need longer to actually cross it
    // (test-resilience Rule 2).
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if manager.validate(&token_value).is_err() {
            break;
        }
        if Instant::now() > deadline {
            panic!("Token with a 10ms lifetime still validated after 2s");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// validate_and_consume rejects wrong user.
#[test]
fn test_wrong_user_rejected() {
    let manager = make_manager();

    let token = manager
        .request_reset("alice@example.com")
        .expect("request reset");
    let token_value = token.value().to_string();

    assert!(
        manager
            .validate_and_consume(&token_value, "eve@example.com")
            .is_err(),
        "Wrong user should be rejected"
    );
}

/// complete_reset followed by revoke_all invalidates outstanding tokens.
#[test]
fn test_complete_reset_invalidates_tokens() {
    let manager = make_manager();
    let user = "charlie@example.com";

    let token1 = manager.request_reset(user).expect("request 1");
    let token1_value = token1.value().to_string();

    // Complete reset revokes all tokens
    manager.complete_reset(user).expect("complete reset");

    // Outstanding token should be invalid
    assert!(
        manager.validate(&token1_value).is_err(),
        "Token should be invalid after complete_reset"
    );
}

/// revoke_all explicitly invalidates all tokens for a user.
#[test]
fn test_revoke_all() {
    // Use zero rate limit to allow rapid token creation
    let store = MemoryResetStore::new();
    let config = ResetConfig::builder()
        .rate_limit_window(Duration::from_millis(0))
        .build();
    let manager = ResetManager::new(store, config);
    let user = "dave@example.com";

    let t1 = manager.request_reset(user).expect("request 1");
    let t2 = manager.request_reset(user).expect("request 2");

    let count = manager.revoke_all(user).expect("revoke all");
    assert!(count >= 2, "Should revoke at least 2 tokens");

    assert!(manager.validate(t1.value()).is_err());
    assert!(manager.validate(t2.value()).is_err());
}

/// Invalid token value is rejected.
#[test]
fn test_invalid_token_rejected() {
    let manager = make_manager();

    assert!(
        manager.validate("not-a-real-token").is_err(),
        "Invalid token should be rejected"
    );
}

/// cleanup removes expired tokens.
#[test]
fn test_cleanup_expired() {
    let manager = make_manager_with_ttl(Duration::from_millis(10));

    manager
        .request_reset("user1@example.com")
        .expect("request 1");
    manager
        .request_reset("user2@example.com")
        .expect("request 2");

    // Poll until both 10ms-lifetime tokens are actually expired and reaped,
    // instead of sleeping a fixed margin (test-resilience Rule 2). `cleanup`
    // is idempotent, so re-running it while tokens are still live is safe.
    // Accumulate across polls: the two tokens may cross their TTL on separate
    // iterations, so a single call's return value can legitimately be 1.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut cleaned = 0;
    while cleaned < 2 {
        cleaned += manager.cleanup().expect("cleanup");
        if cleaned >= 2 {
            break;
        }
        if Instant::now() > deadline {
            panic!("Only {cleaned} expired tokens cleaned up after 2s; expected at least 2");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
