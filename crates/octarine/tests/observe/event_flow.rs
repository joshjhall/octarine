//! Integration tests for event creation and dispatch flow
//!
//! Tests the complete event lifecycle from creation through dispatch.

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::writers::{
    Writer, WriterError, WriterHealthStatus as HealthStatus, register_writer, unregister_writer,
};
use octarine::observe::{
    Event, EventType, Problem, Severity, TenantContext, TenantId, clear_tenant, set_tenant,
    with_tenant,
};
use octarine::{
    debug, error, fail, fail_permission, fail_security, fail_validation, info, success, warn,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// ============================================================================
// Event Creation Tests
// ============================================================================

#[test]
fn test_event_creation_with_message() {
    let event = Event::new(EventType::Info, "Test message");

    assert_eq!(event.message, "Test message");
    assert_eq!(event.event_type, EventType::Info);
    assert_eq!(event.severity, Severity::Info);
}

#[test]
fn test_event_types_have_correct_severity() {
    // Debug events should have Debug severity
    let debug = Event::new(EventType::Debug, "debug");
    assert_eq!(debug.severity, Severity::Debug);

    // Info events should have Info severity
    let info = Event::new(EventType::Info, "info");
    assert_eq!(info.severity, Severity::Info);

    // Warning events should have Warning severity
    let warning = Event::new(EventType::Warning, "warning");
    assert_eq!(warning.severity, Severity::Warning);

    // Error events should have Error severity (LoginFailure maps to Error)
    let login_fail = Event::new(EventType::LoginFailure, "login failure");
    assert_eq!(login_fail.severity, Severity::Error);

    // System errors should have Critical severity
    let system_error = Event::new(EventType::SystemError, "system error");
    assert_eq!(system_error.severity, Severity::Critical);
}

#[test]
fn test_event_has_unique_id() {
    let event1 = Event::new(EventType::Info, "event 1");
    let event2 = Event::new(EventType::Info, "event 2");

    // Each event should have a unique ID
    assert_ne!(event1.id, event2.id);
}

#[test]
fn test_event_timestamp_is_recent() {
    use chrono::Utc;

    let before = Utc::now();
    let event = Event::new(EventType::Info, "test");
    let after = Utc::now();

    // Timestamp should be between before and after
    assert!(event.timestamp >= before);
    assert!(event.timestamp <= after);
}

// ============================================================================
// Error Handling Flow Tests
// ============================================================================

#[test]
fn test_fail_returns_problem() {
    let problem = fail("test_op", "Something went wrong");

    // Problem should contain the message via Display
    let display = problem.to_string();
    assert!(
        display.contains("Something went wrong") || display.contains("test_op"),
        "Problem display should contain error info: {}",
        display
    );
}

#[test]
fn test_fail_validation_returns_validation_problem() {
    let problem = fail_validation("email", "Invalid email format");

    let display = problem.to_string();
    assert!(
        display.contains("Invalid email format") || display.contains("Validation"),
        "Should be a validation problem: {}",
        display
    );
    assert!(matches!(problem, Problem::Validation(_)));
}

#[test]
fn test_fail_security_returns_security_problem() {
    let problem = fail_security("auth", "Unauthorized access attempt");

    let display = problem.to_string();
    assert!(
        display.contains("Unauthorized access attempt")
            || display.contains("auth")
            || display.contains("Authentication"),
        "Should indicate security issue: {}",
        display
    );
}

#[test]
fn test_fail_permission_includes_context() {
    let problem = fail_permission("api", "user123", "admin_panel");

    let display = problem.to_string();
    // Should indicate a permission issue
    assert!(
        display.contains("Permission") || display.contains("denied"),
        "Should indicate permission denial: {}",
        display
    );
}

// ============================================================================
// Tenant Context Tests
// ============================================================================

#[test]
fn test_tenant_context_set_and_clear() {
    let tenant_id = TenantId::new("test-tenant").expect("valid tenant ID");
    let ctx = TenantContext {
        tenant_id,
        tenant_name: Some("Test Tenant".to_string()),
        tenant_tier: Some("free".to_string()),
    };

    set_tenant(ctx);
    // Context is now set for this thread

    clear_tenant();
    // Context is now cleared
}

#[test]
fn test_with_tenant_scoped_context() {
    let tenant_id = TenantId::new("scoped-tenant").expect("valid tenant ID");
    let ctx = TenantContext {
        tenant_id,
        tenant_name: None,
        tenant_tier: None,
    };

    let result = with_tenant(ctx, || {
        // Inside this scope, tenant context is set
        42
    });

    assert_eq!(result, 42);
    // After the closure, tenant context is automatically cleared
}

#[test]
fn test_nested_tenant_contexts() {
    let outer_id = TenantId::new("outer-tenant").expect("valid tenant ID");
    let outer = TenantContext {
        tenant_id: outer_id,
        tenant_name: Some("Outer".to_string()),
        tenant_tier: None,
    };

    let inner_id = TenantId::new("inner-tenant").expect("valid tenant ID");
    let inner = TenantContext {
        tenant_id: inner_id,
        tenant_name: Some("Inner".to_string()),
        tenant_tier: None,
    };

    with_tenant(outer, || {
        // Outer tenant is active
        with_tenant(inner, || {
            // Inner tenant is active (overrides outer)
        });
        // Outer tenant should be restored after inner scope
    });
}

// ============================================================================
// Writer Registration Tests
// ============================================================================

/// Custom writer that tracks write calls
struct CountingWriter {
    name: &'static str,
    count: Arc<AtomicUsize>,
}

impl CountingWriter {
    fn new(name: &'static str) -> (Self, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        (
            Self {
                name,
                count: Arc::clone(&count),
            },
            count,
        )
    }
}

#[async_trait::async_trait]
impl Writer for CountingWriter {
    async fn write(&self, _event: &Event) -> Result<(), WriterError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn flush(&self) -> Result<(), WriterError> {
        Ok(())
    }

    fn health_check(&self) -> HealthStatus {
        HealthStatus::Healthy
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

#[test]
fn test_writer_registration() {
    let (writer, _count) = CountingWriter::new("test_counting_writer");
    register_writer(Box::new(writer));

    // Writer should now be registered
    let writers = octarine::observe::writers::list_writers();
    assert!(writers.contains(&"test_counting_writer"));

    // Cleanup
    unregister_writer("test_counting_writer");
    let writers = octarine::observe::writers::list_writers();
    assert!(!writers.contains(&"test_counting_writer"));
}

#[test]
fn test_writer_health_monitoring() {
    let (writer, _count) = CountingWriter::new("health_test_writer");
    register_writer(Box::new(writer));

    let health = octarine::observe::writers::writer_health();
    assert!(health.contains_key("health_test_writer"));

    // Cleanup
    unregister_writer("health_test_writer");
}

// ============================================================================
// Logging Shortcut Tests
// ============================================================================

#[test]
fn test_logging_shortcuts_do_not_panic() {
    // These should execute without panicking
    // Note: They dispatch to async queue, so we can't verify output here
    debug("test", "Debug message");
    info("test", "Info message");
    warn("test", "Warning message");
    error("test", "Error message");
    success("test", "Success message");
}

#[test]
fn test_logging_with_empty_messages() {
    // Empty messages should be handled gracefully
    info("test", "");
    warn("", "Empty operation");
}

#[test]
fn test_logging_with_special_characters() {
    // Special characters should not cause issues
    info("test", "Message with \"quotes\" and \\ backslash");
    info("test", "Message with\nnewline");
    info("test", "Unicode: 日本語 émoji 🎉");
}
