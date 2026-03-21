//! Integration tests for context capture in events
//!
//! Tests that context set via thread-local/task-local storage
//! properly flows into events created within that scope.

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::writers::{MemoryWriter, Writer, WriterHealthStatus as HealthStatus};
use octarine::observe::{
    Event, EventType, TenantContext, TenantId, clear_source_ip, get_local_network, set_source_ip,
    set_source_ip_chain, set_tenant, with_source_ip,
};
use octarine::runtime::r#async::{
    TaskContextBuilder, clear_context, set_correlation_id, set_session_id, set_user_id,
};
use std::sync::Arc;
use uuid::Uuid;

/// Helper to set tenant context from a simple string ID
fn tenant_id_set(id: &str) {
    let tenant_id = TenantId::new(id).expect("valid tenant ID for test");
    set_tenant(TenantContext {
        tenant_id,
        tenant_name: None,
        tenant_tier: None,
    });
}

/// Helper to get event at index with descriptive error
fn get_event(events: &[Event], index: usize) -> &Event {
    events.get(index).unwrap_or_else(|| {
        panic!(
            "Expected event at index {}, but only {} events exist",
            index,
            events.len()
        )
    })
}

// ============================================================================
// Thread-Local Context Tests (Sync Code)
// ============================================================================

#[tokio::test]
async fn test_thread_local_user_id_captured() {
    // Clear any existing context
    clear_context();

    let writer = Arc::new(MemoryWriter::new());

    // Set user ID via thread-local
    set_user_id("test-user-123");

    // Create an event directly (bypasses async dispatch)
    let event = Event::new(EventType::Info, "Test message");

    // Write to memory writer
    writer.write(&event).await.expect("write should succeed");

    // Check the event captured the user ID
    let events = writer.all_events();
    assert_eq!(events.len(), 1);

    let captured = events.first().expect("should have one event");
    assert_eq!(
        captured.context.user_id.as_ref().map(|u| u.as_str()),
        Some("test-user-123"),
        "Event should capture thread-local user_id"
    );

    clear_context();
}

#[tokio::test]
async fn test_thread_local_session_id_captured() {
    clear_context();

    let writer = Arc::new(MemoryWriter::new());

    set_session_id("sess-abc-123");

    let event = Event::new(EventType::Info, "Test message");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");
    assert_eq!(
        captured.context.session_id.as_deref(),
        Some("sess-abc-123"),
        "Event should capture thread-local session_id"
    );

    clear_context();
}

#[tokio::test]
async fn test_thread_local_tenant_id_captured() {
    clear_context();

    let writer = Arc::new(MemoryWriter::new());

    tenant_id_set("acme-corp");

    let event = Event::new(EventType::Info, "Test message");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");
    assert_eq!(
        captured.context.tenant_id.as_ref().map(|t| t.as_str()),
        Some("acme-corp"),
        "Event should capture thread-local tenant_id"
    );

    clear_context();
}

#[tokio::test]
async fn test_thread_local_correlation_id_captured() {
    clear_context();

    let writer = Arc::new(MemoryWriter::new());

    let corr_id = Uuid::new_v4();
    set_correlation_id(corr_id);

    let event = Event::new(EventType::Info, "Test message");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");
    assert_eq!(
        captured.context.correlation_id, corr_id,
        "Event should capture thread-local correlation_id"
    );

    clear_context();
}

#[tokio::test]
async fn test_all_context_fields_captured_together() {
    clear_context();

    let writer = Arc::new(MemoryWriter::new());

    let corr_id = Uuid::new_v4();
    set_correlation_id(corr_id);
    tenant_id_set("tenant-xyz");
    set_user_id("user-456");
    set_session_id("sess-789");

    let event = Event::new(EventType::Info, "Full context test");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");

    assert_eq!(captured.context.correlation_id, corr_id);
    assert_eq!(
        captured.context.tenant_id.as_ref().map(|t| t.as_str()),
        Some("tenant-xyz")
    );
    assert_eq!(
        captured.context.user_id.as_ref().map(|u| u.as_str()),
        Some("user-456")
    );
    assert_eq!(captured.context.session_id.as_deref(), Some("sess-789"));

    clear_context();
}

// ============================================================================
// Task-Local Context Tests (Async Code)
// ============================================================================

#[tokio::test]
async fn test_async_context_captured() {
    let writer = Arc::new(MemoryWriter::new());

    let corr_id = Uuid::new_v4();

    TaskContextBuilder::new()
        .correlation_id(corr_id)
        .tenant("async-tenant")
        .user("async-user")
        .session("async-session")
        .run(async {
            let event = Event::new(EventType::Info, "Async context test");
            writer.write(&event).await.expect("write should succeed");
        })
        .await;

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");

    assert_eq!(captured.context.correlation_id, corr_id);
    assert_eq!(
        captured.context.tenant_id.as_ref().map(|t| t.as_str()),
        Some("async-tenant")
    );
    assert_eq!(
        captured.context.user_id.as_ref().map(|u| u.as_str()),
        Some("async-user")
    );
    assert_eq!(
        captured.context.session_id.as_deref(),
        Some("async-session")
    );
}

#[tokio::test]
async fn test_async_context_persists_across_await() {
    let writer = Arc::new(MemoryWriter::new());

    let corr_id = Uuid::new_v4();

    TaskContextBuilder::new()
        .correlation_id(corr_id)
        .user("persistent-user")
        .run(async {
            // First event
            let event1 = Event::new(EventType::Info, "Before await");
            writer.write(&event1).await.expect("write should succeed");

            // Await something
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            // Second event - should still have context
            let event2 = Event::new(EventType::Info, "After await");
            writer.write(&event2).await.expect("write should succeed");
        })
        .await;

    let events = writer.all_events();
    assert_eq!(events.len(), 2);

    // Both events should have the same context
    for event in &events {
        assert_eq!(event.context.correlation_id, corr_id);
        assert_eq!(
            event.context.user_id.as_ref().map(|u| u.as_str()),
            Some("persistent-user")
        );
    }
}

#[tokio::test]
async fn test_nested_async_context() {
    let writer = Arc::new(MemoryWriter::new());

    let outer_id = Uuid::new_v4();
    let inner_id = Uuid::new_v4();

    TaskContextBuilder::new()
        .correlation_id(outer_id)
        .user("outer-user")
        .run(async {
            // Event with outer context
            let event1 = Event::new(EventType::Info, "Outer context");
            writer.write(&event1).await.expect("write should succeed");

            // Nested context
            TaskContextBuilder::new()
                .correlation_id(inner_id)
                .user("inner-user")
                .run(async {
                    let event2 = Event::new(EventType::Info, "Inner context");
                    writer.write(&event2).await.expect("write should succeed");
                })
                .await;

            // Back to outer context
            let event3 = Event::new(EventType::Info, "Back to outer");
            writer.write(&event3).await.expect("write should succeed");
        })
        .await;

    let events = writer.all_events();
    assert_eq!(events.len(), 3);

    // First event: outer context
    let event0 = get_event(&events, 0);
    assert_eq!(event0.context.correlation_id, outer_id);
    assert_eq!(
        event0.context.user_id.as_ref().map(|u| u.as_str()),
        Some("outer-user")
    );

    // Second event: inner context
    let event1 = get_event(&events, 1);
    assert_eq!(event1.context.correlation_id, inner_id);
    assert_eq!(
        event1.context.user_id.as_ref().map(|u| u.as_str()),
        Some("inner-user")
    );

    // Third event: back to outer context
    let event2 = get_event(&events, 2);
    assert_eq!(event2.context.correlation_id, outer_id);
    assert_eq!(
        event2.context.user_id.as_ref().map(|u| u.as_str()),
        Some("outer-user")
    );
}

// ============================================================================
// Context Isolation Tests
// ============================================================================

#[tokio::test]
async fn test_context_cleared_properly() {
    clear_context();

    let writer = Arc::new(MemoryWriter::new());

    // Set context
    set_user_id("temp-user");

    let event1 = Event::new(EventType::Info, "With context");
    writer.write(&event1).await.expect("write should succeed");

    // Clear context
    clear_context();

    let event2 = Event::new(EventType::Info, "Without context");
    writer.write(&event2).await.expect("write should succeed");

    let events = writer.all_events();
    assert_eq!(events.len(), 2);

    // First event has user_id
    let event0 = get_event(&events, 0);
    assert_eq!(
        event0.context.user_id.as_ref().map(|u| u.as_str()),
        Some("temp-user")
    );

    // Second event should NOT have user_id (it was cleared)
    let event1 = get_event(&events, 1);
    assert!(
        event1.context.user_id.is_none(),
        "User ID should be cleared"
    );
}

#[tokio::test]
async fn test_concurrent_tasks_isolated() {
    let writer = Arc::new(MemoryWriter::new());

    let w1 = Arc::clone(&writer);
    let w2 = Arc::clone(&writer);

    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();

    // Two concurrent tasks with different contexts
    let handle1 = tokio::spawn(async move {
        TaskContextBuilder::new()
            .correlation_id(id1)
            .user("user-1")
            .run(async {
                for i in 0..5 {
                    let event = Event::new(EventType::Info, format!("Task1 event {}", i));
                    w1.write(&event).await.expect("write should succeed");
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await;
        id1
    });

    let handle2 = tokio::spawn(async move {
        TaskContextBuilder::new()
            .correlation_id(id2)
            .user("user-2")
            .run(async {
                for i in 0..5 {
                    let event = Event::new(EventType::Info, format!("Task2 event {}", i));
                    w2.write(&event).await.expect("write should succeed");
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await;
        id2
    });

    let result1 = handle1.await.expect("task1 should complete");
    let result2 = handle2.await.expect("task2 should complete");

    let events = writer.all_events();
    assert_eq!(events.len(), 10, "Should have 10 events total");

    // Verify each event has the correct context for its task
    for event in &events {
        if event.message.contains("Task1") {
            assert_eq!(
                event.context.correlation_id, result1,
                "Task1 events should have id1"
            );
            assert_eq!(
                event.context.user_id.as_ref().map(|u| u.as_str()),
                Some("user-1")
            );
        } else if event.message.contains("Task2") {
            assert_eq!(
                event.context.correlation_id, result2,
                "Task2 events should have id2"
            );
            assert_eq!(
                event.context.user_id.as_ref().map(|u| u.as_str()),
                Some("user-2")
            );
        }
    }
}

// ============================================================================
// Context Fallback Tests
// ============================================================================

#[tokio::test]
async fn test_correlation_id_generated_when_not_set() {
    clear_context();

    let writer = Arc::new(MemoryWriter::new());

    let event = Event::new(EventType::Info, "No explicit correlation ID");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");

    // Correlation ID should be auto-generated (non-nil UUID)
    assert_ne!(
        captured.context.correlation_id,
        Uuid::nil(),
        "Should have auto-generated correlation ID"
    );
}

#[tokio::test]
async fn test_no_context_fields_when_not_set() {
    clear_context();

    let writer = Arc::new(MemoryWriter::new());

    let event = Event::new(EventType::Info, "No context set");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");

    // Optional fields should be None when not set
    // Note: tenant_id and user_id may come from env vars as fallback
    // but session_id should definitely be None if not set
    assert!(
        captured.context.session_id.is_none(),
        "session_id should be None when not set"
    );
}

// ============================================================================
// Writer Health During Context Operations
// ============================================================================

#[test]
fn test_writer_health_unaffected_by_context() {
    let writer = MemoryWriter::new();

    // Check health before context
    assert!(matches!(writer.health_check(), HealthStatus::Healthy));

    // Set some context
    set_correlation_id(Uuid::new_v4());
    set_user_id("test");

    // Health should still be good
    assert!(matches!(writer.health_check(), HealthStatus::Healthy));

    clear_context();
}

// ============================================================================
// Source IP Context Tests
// ============================================================================

#[tokio::test]
async fn test_source_ip_captured_in_event() {
    clear_context();
    clear_source_ip();

    let writer = Arc::new(MemoryWriter::new());

    // Set source IP
    set_source_ip("192.168.1.100");

    // Create and write event
    let event = Event::new(EventType::Info, "Request from client");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");

    assert_eq!(
        captured.context.source_ip.as_deref(),
        Some("192.168.1.100"),
        "Source IP should be captured"
    );

    clear_source_ip();
}

#[tokio::test]
async fn test_source_ip_chain_captured() {
    clear_context();
    clear_source_ip();

    let writer = Arc::new(MemoryWriter::new());

    // Simulate X-Forwarded-For: client, proxy1, proxy2
    let chain = vec![
        "203.0.113.50".to_string(), // Original client
        "10.0.0.1".to_string(),     // First proxy
        "10.0.0.2".to_string(),     // Second proxy (closest to server)
    ];
    set_source_ip_chain(chain);

    let event = Event::new(EventType::Info, "Request through proxies");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");

    // source_ip should be the last in chain (closest to server)
    assert_eq!(
        captured.context.source_ip.as_deref(),
        Some("10.0.0.2"),
        "Source IP should be last in chain"
    );

    // Full chain should be preserved
    assert_eq!(captured.context.source_ip_chain.len(), 3);
    assert_eq!(
        captured.context.source_ip_chain.first(),
        Some(&"203.0.113.50".to_string())
    );
    assert_eq!(
        captured.context.source_ip_chain.get(1),
        Some(&"10.0.0.1".to_string())
    );
    assert_eq!(
        captured.context.source_ip_chain.get(2),
        Some(&"10.0.0.2".to_string())
    );

    clear_source_ip();
}

#[tokio::test]
async fn test_with_source_ip_scoped() {
    clear_context();
    clear_source_ip();

    let writer = Arc::new(MemoryWriter::new());

    // Before scope - no source IP
    let event1 = Event::new(EventType::Info, "Before scope");
    writer.write(&event1).await.expect("write should succeed");

    // Inside scope - has source IP
    with_source_ip("10.0.0.50", || {
        let event2 = Event::new(EventType::Info, "Inside scope");
        // Can't use async inside with_source_ip, so we test sync context capture
        assert!(
            event2.context.source_ip.is_some(),
            "Should have source IP in scope"
        );
    });

    // After scope - source IP should be cleared
    let event3 = Event::new(EventType::Info, "After scope");
    writer.write(&event3).await.expect("write should succeed");

    let events = writer.all_events();

    // First event: no source IP
    let e1 = get_event(&events, 0);
    assert!(
        e1.context.source_ip.is_none(),
        "Before scope should have no source IP"
    );

    // Third event (second written): no source IP (cleared after scope)
    let e3 = get_event(&events, 1);
    assert!(
        e3.context.source_ip.is_none(),
        "After scope should have no source IP"
    );
}

#[tokio::test]
async fn test_source_ip_cleared() {
    clear_context();
    clear_source_ip();

    let writer = Arc::new(MemoryWriter::new());

    // Set then clear
    set_source_ip("1.2.3.4");
    clear_source_ip();

    let event = Event::new(EventType::Info, "After clear");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");

    assert!(
        captured.context.source_ip.is_none(),
        "Source IP should be cleared"
    );
    assert!(
        captured.context.source_ip_chain.is_empty(),
        "Source IP chain should be cleared"
    );
}

// ============================================================================
// Local Network Context Tests
// ============================================================================

#[test]
fn test_local_network_context_captured() {
    let network = get_local_network();

    // Should have at least some network info
    // (loopback might be the only interface in some test environments)
    // Note: We don't assert on counts since some CI environments may have minimal networking

    // If we have interfaces, verify they have names
    for iface in &network.interfaces {
        assert!(!iface.name.is_empty(), "Interface should have a name");
    }
}

#[tokio::test]
async fn test_local_ip_in_event() {
    clear_context();

    let writer = Arc::new(MemoryWriter::new());

    let event = Event::new(EventType::Info, "Event with local IP");
    writer.write(&event).await.expect("write should succeed");

    let events = writer.all_events();
    let captured = events.first().expect("should have one event");

    // local_ip may or may not be set depending on network config
    // but if set, it should be a valid IP
    if let Some(ref ip) = captured.context.local_ip {
        assert!(!ip.is_empty(), "Local IP should not be empty if set");
        // Basic validation - should contain dots (IPv4) or colons (IPv6)
        assert!(
            ip.contains('.') || ip.contains(':'),
            "Local IP should look like an IP address: {}",
            ip
        );
    }
}
