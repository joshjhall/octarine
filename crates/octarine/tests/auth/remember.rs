#![allow(clippy::panic, clippy::expect_used)]

use octarine::auth::{MemoryRememberStore, RememberConfig, RememberManager};

fn make_manager_with_rotation() -> RememberManager<MemoryRememberStore> {
    let store = MemoryRememberStore::new();
    let config = RememberConfig::builder().rotate_on_use(true).build();
    RememberManager::new(store, config)
}

fn make_manager_without_rotation() -> RememberManager<MemoryRememberStore> {
    let store = MemoryRememberStore::new();
    let config = RememberConfig::builder().rotate_on_use(false).build();
    RememberManager::new(store, config)
}

/// Issue token → validate → token is valid.
#[test]
fn test_issue_and_validate() {
    let manager = make_manager_without_rotation();

    let pair = manager
        .issue_token("alice", Some("Chrome on Mac"))
        .expect("issue token");
    let cookie = pair.cookie_value();

    let user_id = manager.validate(&cookie).expect("validate");
    assert_eq!(user_id, "alice");
}

/// Token rotation: validate_and_refresh returns new cookie, old becomes invalid.
#[test]
fn test_token_rotation_on_use() {
    let manager = make_manager_with_rotation();

    let pair = manager.issue_token("alice", None).expect("issue token");
    let old_cookie = pair.cookie_value();

    // validate_and_refresh should return new token pair
    let (user_id, new_pair) = manager
        .validate_and_refresh(&old_cookie)
        .expect("validate and refresh");
    assert_eq!(user_id, "alice");
    assert!(
        new_pair.is_some(),
        "Should return new token pair when rotation is enabled"
    );

    let new_cookie = new_pair.expect("new pair").cookie_value();

    // Old cookie should now be invalid
    assert!(
        manager.validate(&old_cookie).is_err(),
        "Old cookie should be invalid after rotation"
    );

    // New cookie should work
    let user_id2 = manager.validate(&new_cookie).expect("validate new cookie");
    assert_eq!(user_id2, "alice");
}

/// Without rotation: validate_and_refresh returns None for new pair.
#[test]
fn test_no_rotation_when_disabled() {
    let manager = make_manager_without_rotation();

    let pair = manager.issue_token("bob", None).expect("issue token");
    let cookie = pair.cookie_value();

    let (user_id, new_pair) = manager
        .validate_and_refresh(&cookie)
        .expect("validate and refresh");
    assert_eq!(user_id, "bob");
    assert!(
        new_pair.is_none(),
        "Should not return new pair when rotation is disabled"
    );

    // Original cookie still works
    let user_id2 = manager.validate(&cookie).expect("validate again");
    assert_eq!(user_id2, "bob");
}

/// Revoke single token → that cookie fails validation.
#[test]
fn test_revoke_single_token() {
    let manager = make_manager_without_rotation();

    let pair1 = manager
        .issue_token("alice", Some("Device 1"))
        .expect("token 1");
    let pair2 = manager
        .issue_token("alice", Some("Device 2"))
        .expect("token 2");

    // Revoke first token
    let revoked = manager.revoke(&pair1.cookie_value()).expect("revoke");
    assert!(revoked);

    // First token invalid, second still valid
    assert!(manager.validate(&pair1.cookie_value()).is_err());
    assert!(manager.validate(&pair2.cookie_value()).is_ok());
}

/// revoke_all for user invalidates all tokens.
#[test]
fn test_revoke_all_for_user() {
    let manager = make_manager_without_rotation();

    let pair1 = manager
        .issue_token("alice", Some("Device 1"))
        .expect("token 1");
    let pair2 = manager
        .issue_token("alice", Some("Device 2"))
        .expect("token 2");
    let bob_pair = manager
        .issue_token("bob", Some("Device 1"))
        .expect("bob token");

    let count = manager.revoke_all("alice").expect("revoke all");
    assert_eq!(count, 2, "Should revoke 2 tokens for alice");

    // Alice's tokens invalid
    assert!(manager.validate(&pair1.cookie_value()).is_err());
    assert!(manager.validate(&pair2.cookie_value()).is_err());

    // Bob's token still valid
    assert!(manager.validate(&bob_pair.cookie_value()).is_ok());
}

/// get_active_tokens returns correct set.
#[test]
fn test_get_active_tokens() {
    let manager = make_manager_without_rotation();

    manager
        .issue_token("alice", Some("Phone"))
        .expect("token 1");
    manager
        .issue_token("alice", Some("Laptop"))
        .expect("token 2");

    let tokens = manager.get_active_tokens("alice").expect("get tokens");
    assert_eq!(tokens.len(), 2, "Should have 2 active tokens");
}

/// Invalid cookie value is rejected.
#[test]
fn test_invalid_cookie_rejected() {
    let manager = make_manager_without_rotation();

    assert!(
        manager.validate("not-a-valid-cookie").is_err(),
        "Invalid cookie should be rejected"
    );
}
