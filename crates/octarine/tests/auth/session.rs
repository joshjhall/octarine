#![allow(clippy::panic, clippy::expect_used)]

use std::sync::Arc;

use octarine::auth::{MemorySessionStore, SessionConfig, SessionManager};

fn make_manager_with_binding() -> SessionManager<MemorySessionStore> {
    let store = Arc::new(MemorySessionStore::new());
    let config = SessionConfig::builder()
        .bind_user_agent(true)
        .bind_ip(true)
        .build();
    SessionManager::new(store, config)
}

fn make_manager() -> SessionManager<MemorySessionStore> {
    let store = Arc::new(MemorySessionStore::new());
    SessionManager::new(store, SessionConfig::default())
}

/// Create session with binding → validate with same binding → success.
#[test]
fn test_session_binding_match() {
    let manager = make_manager_with_binding();

    let session = manager
        .create_session_with_binding("alice", Some("Chrome/120"), Some("192.168.1.1"))
        .expect("create session");

    // Validate with same binding should succeed
    let validated = manager
        .validate_session(&session.id, Some("Chrome/120"), Some("192.168.1.1"))
        .expect("validate session");

    assert_eq!(validated.user_id, "alice");
}

/// Validate with different user_agent → binding mismatch error.
#[test]
fn test_session_binding_mismatch_user_agent() {
    let manager = make_manager_with_binding();

    let session = manager
        .create_session_with_binding("alice", Some("Chrome/120"), Some("192.168.1.1"))
        .expect("create session");

    // Different user agent should fail
    let result = manager.validate_session(&session.id, Some("Firefox/115"), Some("192.168.1.1"));
    assert!(
        result.is_err(),
        "Different user agent should fail binding check"
    );
}

/// Validate with different IP → binding mismatch error.
#[test]
fn test_session_binding_mismatch_ip() {
    let manager = make_manager_with_binding();

    let session = manager
        .create_session_with_binding("alice", Some("Chrome/120"), Some("192.168.1.1"))
        .expect("create session");

    // Different IP should fail
    let result = manager.validate_session(&session.id, Some("Chrome/120"), Some("10.0.0.1"));
    assert!(result.is_err(), "Different IP should fail binding check");
}

/// terminate_all_for_user clears all sessions for that user.
#[test]
fn test_terminate_all_sessions() {
    let manager = make_manager();

    manager.create_session("alice").expect("session 1");
    manager.create_session("alice").expect("session 2");
    manager.create_session("bob").expect("bob session");

    let count = manager
        .terminate_all_for_user("alice")
        .expect("terminate all");
    assert_eq!(count, 2, "Should terminate 2 sessions for alice");

    // Bob's session should still exist
    let bob_count = manager.count_user_sessions("bob").expect("count bob");
    assert_eq!(bob_count, 1, "Bob should still have 1 session");
}

/// regenerate_session creates new ID while preserving user.
#[test]
fn test_regenerate_session() {
    let manager = make_manager_with_binding();

    let session = manager
        .create_session_with_binding("alice", Some("Chrome/120"), Some("192.168.1.1"))
        .expect("create session");
    let old_id = session.id.clone();

    let new_session = manager
        .regenerate_session(&old_id, Some("Chrome/120"), Some("192.168.1.1"))
        .expect("regenerate");

    assert_ne!(new_session.id, old_id, "Should have new session ID");
    assert_eq!(new_session.user_id, "alice", "Should preserve user");

    // Old session should be invalid
    let result = manager.validate_session(&old_id, Some("Chrome/120"), Some("192.168.1.1"));
    assert!(result.is_err(), "Old session should be terminated");
}

/// terminate_session removes a specific session.
#[test]
fn test_terminate_single_session() {
    let manager = make_manager();

    let s1 = manager.create_session("alice").expect("session 1");
    let s2 = manager.create_session("alice").expect("session 2");

    let terminated = manager.terminate_session(&s1.id).expect("terminate");
    assert!(terminated, "Should report session was terminated");

    // s1 should be invalid, s2 still valid
    assert!(manager.validate_session(&s1.id, None, None).is_err());
    assert!(manager.validate_session(&s2.id, None, None).is_ok());
}

/// count_user_sessions returns correct count.
#[test]
fn test_count_sessions() {
    let manager = make_manager();

    assert_eq!(
        manager.count_user_sessions("alice").expect("count"),
        0,
        "Should start at 0"
    );

    manager.create_session("alice").expect("session 1");
    manager.create_session("alice").expect("session 2");

    assert_eq!(
        manager.count_user_sessions("alice").expect("count"),
        2,
        "Should have 2 sessions"
    );
}
