//! Integration tests for MemoryWriter
//!
//! Tests the in-memory writer implementation including:
//! - Basic write/read operations
//! - Capacity limits and eviction
//! - Query filtering and pagination
//! - Thread safety under concurrent access

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::Event as OctEvent;

/// Helper to get event at index with descriptive error
fn get_event(events: &[OctEvent], index: usize) -> &OctEvent {
    events.get(index).unwrap_or_else(|| {
        panic!(
            "Expected event at index {}, but only {} events exist",
            index,
            events.len()
        )
    })
}

use octarine::observe::writers::{
    AuditQuery, MemoryWriter, Queryable, Writer, WriterHealthStatus as HealthStatus,
};
use octarine::observe::{Event, EventType, Severity};
use std::sync::Arc;

// ============================================================================
// Basic Operations
// ============================================================================

#[tokio::test]
async fn test_memory_writer_write_and_retrieve() {
    let writer = MemoryWriter::new();

    // Write an event
    let event = Event::new(EventType::Info, "Test event");
    writer.write(&event).await.expect("write should succeed");

    // Retrieve all events
    let events = writer.all_events();
    assert_eq!(events.len(), 1);
    assert_eq!(get_event(&events, 0).message, "Test event");
}

#[tokio::test]
async fn test_memory_writer_preserves_event_details() {
    let writer = MemoryWriter::new();

    let original = Event::new(EventType::Warning, "Important warning");
    let original_id = original.id;
    let original_timestamp = original.timestamp;

    writer.write(&original).await.expect("write should succeed");

    let events = writer.all_events();
    assert_eq!(events.len(), 1);

    let retrieved = get_event(&events, 0);
    assert_eq!(retrieved.id, original_id);
    assert_eq!(retrieved.timestamp, original_timestamp);
    assert_eq!(retrieved.message, "Important warning");
    assert_eq!(retrieved.event_type, EventType::Warning);
    assert_eq!(retrieved.severity, Severity::Warning);
}

#[tokio::test]
async fn test_memory_writer_multiple_events_order() {
    let writer = MemoryWriter::new();

    // Write multiple events
    for i in 0..5 {
        let event = Event::new(EventType::Info, format!("Event {}", i));
        writer.write(&event).await.expect("write should succeed");
    }

    // Events should be in insertion order
    let events = writer.all_events();
    assert_eq!(events.len(), 5);

    for (i, event) in events.iter().enumerate() {
        assert!(event.message.contains(&format!("Event {}", i)));
    }
}

// ============================================================================
// Capacity and Eviction
// ============================================================================

#[tokio::test]
async fn test_memory_writer_respects_capacity() {
    let writer = MemoryWriter::with_capacity(3);

    // Write 5 events to a capacity-3 writer
    for i in 0..5 {
        let event = Event::new(EventType::Info, format!("Event {}", i));
        writer.write(&event).await.expect("write should succeed");
    }

    // Should only have the last 3 events
    assert_eq!(writer.len(), 3);

    let events = writer.all_events();
    assert!(get_event(&events, 0).message.contains("Event 2"));
    assert!(get_event(&events, 1).message.contains("Event 3"));
    assert!(get_event(&events, 2).message.contains("Event 4"));
}

#[tokio::test]
async fn test_memory_writer_evicts_oldest_first() {
    let writer = MemoryWriter::with_capacity(2);

    // Write event A
    writer
        .write(&Event::new(EventType::Info, "A"))
        .await
        .expect("write should succeed");

    // Write event B
    writer
        .write(&Event::new(EventType::Info, "B"))
        .await
        .expect("write should succeed");

    // Write event C - this should evict A
    writer
        .write(&Event::new(EventType::Info, "C"))
        .await
        .expect("write should succeed");

    let events = writer.all_events();
    assert_eq!(events.len(), 2);

    // A should be evicted, B and C should remain
    let messages: Vec<&str> = events.iter().map(|e| e.message.as_str()).collect();
    assert!(!messages.contains(&"A"));
    assert!(messages.contains(&"B"));
    assert!(messages.contains(&"C"));
}

// ============================================================================
// Query Filtering
// ============================================================================

#[tokio::test]
async fn test_query_by_severity() {
    let writer = MemoryWriter::new();

    // Write events with different severities
    writer
        .write(&Event::new(EventType::Debug, "debug"))
        .await
        .expect("write should succeed");
    writer
        .write(&Event::new(EventType::Info, "info"))
        .await
        .expect("write should succeed");
    writer
        .write(&Event::new(EventType::Warning, "warning"))
        .await
        .expect("write should succeed");
    writer
        .write(&Event::new(EventType::SystemError, "error"))
        .await
        .expect("write should succeed");

    // Query for Warning and above
    let query = AuditQuery {
        min_severity: Some(Severity::Warning),
        ..Default::default()
    };

    let result = writer.query(&query).await.expect("query should succeed");
    assert_eq!(result.events.len(), 2);

    // Should include warning and error, not debug or info
    let messages: Vec<&str> = result.events.iter().map(|e| e.message.as_str()).collect();
    assert!(messages.contains(&"warning"));
    assert!(messages.contains(&"error"));
    assert!(!messages.contains(&"debug"));
    assert!(!messages.contains(&"info"));
}

#[tokio::test]
async fn test_query_by_event_type() {
    let writer = MemoryWriter::new();

    writer
        .write(&Event::new(EventType::LoginSuccess, "login ok"))
        .await
        .expect("write should succeed");
    writer
        .write(&Event::new(EventType::LoginFailure, "login failed"))
        .await
        .expect("write should succeed");
    writer
        .write(&Event::new(EventType::Info, "other"))
        .await
        .expect("write should succeed");

    // Query for login failures only
    let query = AuditQuery {
        event_types: Some(vec![EventType::LoginFailure]),
        ..Default::default()
    };

    let result = writer.query(&query).await.expect("query should succeed");
    assert_eq!(result.events.len(), 1);
    assert_eq!(get_event(&result.events, 0).message, "login failed");
}

#[tokio::test]
async fn test_query_security_relevant_only() {
    let writer = MemoryWriter::new();

    // Write a normal event
    writer
        .write(&Event::new(EventType::Info, "normal"))
        .await
        .expect("write should succeed");

    // Write security-relevant events (LoginFailure is security-relevant by context)
    writer
        .write(&Event::new(EventType::LoginFailure, "auth fail"))
        .await
        .expect("write should succeed");

    // Write authentication error
    writer
        .write(&Event::new(EventType::AuthenticationError, "auth error"))
        .await
        .expect("write should succeed");

    let query = AuditQuery {
        security_relevant_only: true,
        ..Default::default()
    };

    let result = writer.query(&query).await.expect("query should succeed");

    // Only events marked as security_relevant in context should be returned
    // Note: security_relevant flag is in EventContext, not EventType
    // The default EventContext has security_relevant: false
    // So this test verifies the filter works (returns empty or only events with flag set)
    for event in &result.events {
        assert!(
            event.context.security_relevant,
            "Returned event should have security_relevant flag set"
        );
    }
}

// ============================================================================
// Query Pagination
// ============================================================================

#[tokio::test]
async fn test_query_with_limit() {
    let writer = MemoryWriter::new();

    // Write 10 events
    for i in 0..10 {
        writer
            .write(&Event::new(EventType::Info, format!("Event {}", i)))
            .await
            .expect("write should succeed");
    }

    // Query with limit
    let query = AuditQuery {
        limit: Some(3),
        ..Default::default()
    };

    let result = writer.query(&query).await.expect("query should succeed");
    assert_eq!(result.events.len(), 3);
    assert!(result.has_more);
    assert_eq!(result.total_count, Some(10));
}

#[tokio::test]
async fn test_query_with_offset() {
    let writer = MemoryWriter::new();

    // Write 10 events
    for i in 0..10 {
        writer
            .write(&Event::new(EventType::Info, format!("Event {}", i)))
            .await
            .expect("write should succeed");
    }

    // Query with offset and ascending order
    let query = AuditQuery {
        limit: Some(3),
        offset: Some(5),
        ascending: true,
        ..Default::default()
    };

    let result = writer.query(&query).await.expect("query should succeed");
    assert_eq!(result.events.len(), 3);

    // With ascending order and offset 5, should get events 5, 6, 7
    assert!(get_event(&result.events, 0).message.contains("Event 5"));
    assert!(get_event(&result.events, 1).message.contains("Event 6"));
    assert!(get_event(&result.events, 2).message.contains("Event 7"));
}

#[tokio::test]
async fn test_query_descending_order() {
    let writer = MemoryWriter::new();

    for i in 0..5 {
        writer
            .write(&Event::new(EventType::Info, format!("Event {}", i)))
            .await
            .expect("write should succeed");
    }

    // Query in descending order (newest first)
    let query = AuditQuery {
        ascending: false,
        ..Default::default()
    };

    let result = writer.query(&query).await.expect("query should succeed");

    // Most recent event should be first
    assert!(get_event(&result.events, 0).message.contains("Event 4"));
    assert!(get_event(&result.events, 4).message.contains("Event 0"));
}

// ============================================================================
// Health and Lifecycle
// ============================================================================

#[tokio::test]
async fn test_memory_writer_health_check() {
    let writer = MemoryWriter::new();
    assert!(matches!(writer.health_check(), HealthStatus::Healthy));

    // Health should remain healthy after writes
    writer
        .write(&Event::new(EventType::Info, "test"))
        .await
        .expect("write should succeed");
    assert!(matches!(writer.health_check(), HealthStatus::Healthy));
}

#[tokio::test]
async fn test_memory_writer_clear() {
    let writer = MemoryWriter::new();

    writer
        .write(&Event::new(EventType::Info, "event 1"))
        .await
        .expect("write should succeed");
    writer
        .write(&Event::new(EventType::Info, "event 2"))
        .await
        .expect("write should succeed");

    assert_eq!(writer.len(), 2);

    writer.clear();

    assert_eq!(writer.len(), 0);
    assert!(writer.is_empty());
}

#[tokio::test]
async fn test_memory_writer_recent() {
    let writer = MemoryWriter::new();

    for i in 0..10 {
        writer
            .write(&Event::new(EventType::Info, format!("Event {}", i)))
            .await
            .expect("write should succeed");
    }

    let recent = writer.recent(3);
    assert_eq!(recent.len(), 3);

    // Most recent events (9, 8, 7)
    assert!(get_event(&recent, 0).message.contains("Event 9"));
    assert!(get_event(&recent, 1).message.contains("Event 8"));
    assert!(get_event(&recent, 2).message.contains("Event 7"));
}

// ============================================================================
// Batch Operations
// ============================================================================

#[tokio::test]
async fn test_batch_write() {
    let writer = MemoryWriter::new();

    let events: Vec<Event> = (0..5)
        .map(|i| Event::new(EventType::Info, format!("Batch event {}", i)))
        .collect();

    let count = writer
        .write_batch(&events)
        .await
        .expect("batch write should succeed");

    assert_eq!(count, 5);
    assert_eq!(writer.len(), 5);
}

#[tokio::test]
async fn test_batch_write_respects_capacity() {
    let writer = MemoryWriter::with_capacity(3);

    let events: Vec<Event> = (0..5)
        .map(|i| Event::new(EventType::Info, format!("Batch event {}", i)))
        .collect();

    writer
        .write_batch(&events)
        .await
        .expect("batch write should succeed");

    // Should only have last 3 events due to capacity
    assert_eq!(writer.len(), 3);
    let stored = writer.all_events();
    assert!(get_event(&stored, 0).message.contains("Batch event 2"));
}

// ============================================================================
// Thread Safety
// ============================================================================

#[tokio::test]
async fn test_concurrent_writes() {
    let writer = Arc::new(MemoryWriter::new());
    let mut handles = vec![];

    // Spawn multiple tasks writing concurrently
    for i in 0..10 {
        let w = Arc::clone(&writer);
        handles.push(tokio::spawn(async move {
            for j in 0..10 {
                let event = Event::new(EventType::Info, format!("Task {} Event {}", i, j));
                w.write(&event).await.expect("write should succeed");
            }
        }));
    }

    // Wait for all writes
    for handle in handles {
        handle.await.expect("task should complete");
    }

    // All events should be written
    assert_eq!(writer.len(), 100);
}

#[tokio::test]
async fn test_concurrent_write_and_read() {
    let writer = Arc::new(MemoryWriter::new());

    // Writer task
    let w = Arc::clone(&writer);
    let writer_handle = tokio::spawn(async move {
        for i in 0..100 {
            let event = Event::new(EventType::Info, format!("Event {}", i));
            w.write(&event).await.expect("write should succeed");
            tokio::time::sleep(std::time::Duration::from_micros(100)).await;
        }
    });

    // Reader task
    let r = Arc::clone(&writer);
    let reader_handle = tokio::spawn(async move {
        for _ in 0..50 {
            let _ = r.len();
            let _ = r.all_events();
            tokio::time::sleep(std::time::Duration::from_micros(200)).await;
        }
    });

    // Both should complete without deadlock or panic
    writer_handle.await.expect("writer should complete");
    reader_handle.await.expect("reader should complete");
}
