#![allow(clippy::panic, clippy::expect_used)]

use std::sync::Arc;

use octarine::auth::{LockoutConfig, LockoutManager, MemoryLockoutStore};

fn make_manager(max_attempts: u32) -> LockoutManager<MemoryLockoutStore> {
    let store = Arc::new(MemoryLockoutStore::new());
    let config = LockoutConfig::builder().max_attempts(max_attempts).build();
    LockoutManager::new(store, config)
}

/// Record failures up to max_attempts → lockout triggered.
#[test]
fn test_lockout_after_repeated_failures() {
    let manager = make_manager(3);
    let user = "alice@example.com";

    // First two failures: still allowed
    let d1 = manager.record_failure(user).expect("failure 1");
    assert!(!d1.is_locked(), "Should still be allowed after 1 failure");

    let d2 = manager.record_failure(user).expect("failure 2");
    assert!(!d2.is_locked(), "Should still be allowed after 2 failures");

    // Third failure triggers lockout
    let d3 = manager.record_failure(user).expect("failure 3");
    assert!(d3.is_locked(), "Should be locked after 3 failures");

    // Subsequent check also reports locked
    let check = manager.check(user).expect("check");
    assert!(check.is_locked(), "Check should report locked");
}

/// record_success clears consecutive failure count.
#[test]
fn test_success_clears_consecutive_count() {
    let manager = make_manager(5);
    let user = "bob@example.com";

    // Record 2 failures
    manager.record_failure(user).expect("failure 1");
    manager.record_failure(user).expect("failure 2");

    // Successful login resets consecutive count
    manager.record_success(user).expect("success");

    // Consecutive count should be reset
    let status = manager.get_status(user).expect("status");
    assert_eq!(
        status.consecutive_failures, 0,
        "Consecutive failures should be 0 after success"
    );

    // Should still be allowed (below max_attempts threshold)
    let decision = manager.check(user).expect("check");
    assert!(!decision.is_locked(), "Should be allowed after success");
}

/// clear_lockout admin override unlocks immediately.
#[test]
fn test_admin_clear_lockout() {
    let manager = make_manager(2);
    let user = "charlie@example.com";

    // Trigger lockout
    manager.record_failure(user).expect("failure 1");
    manager.record_failure(user).expect("failure 2");
    assert!(manager.check(user).expect("check").is_locked());

    // Admin clears lockout
    let cleared = manager.clear_lockout(user).expect("clear");
    assert!(cleared, "Should report lockout was cleared");

    // Now allowed again
    let decision = manager.check(user).expect("check after clear");
    assert!(!decision.is_locked(), "Should be allowed after admin clear");
}

/// Failures with context (IP, user agent) are tracked.
#[test]
fn test_failure_with_context() {
    let manager = make_manager(3);
    let user = "dave@example.com";

    let d = manager
        .record_failure_with_context(user, Some("192.168.1.1"), Some("Chrome/120"))
        .expect("failure with context");
    assert!(!d.is_locked());

    let status = manager.get_status(user).expect("status");
    assert_eq!(status.consecutive_failures, 1);
}

/// Different identifiers are isolated from each other.
#[test]
fn test_lockout_isolation() {
    let manager = make_manager(2);

    // Lock out alice
    manager.record_failure("alice").expect("alice fail 1");
    manager.record_failure("alice").expect("alice fail 2");
    assert!(manager.check("alice").expect("check alice").is_locked());

    // Bob is unaffected
    let bob = manager.check("bob").expect("check bob");
    assert!(
        !bob.is_locked(),
        "Bob should not be locked by Alice's failures"
    );
}

/// Exponential backoff: duration increases with failure count.
#[test]
fn test_exponential_backoff_duration() {
    let manager = make_manager(2);

    let d1 = manager.calculate_lockout_duration(2);
    let d2 = manager.calculate_lockout_duration(4);

    assert!(
        d2 > d1,
        "More failures should produce longer lockout duration"
    );
}
