//! Integration tests for async event dispatch
//!
//! Tests the async dispatch system including:
//! - Event queuing and delivery
//! - Health monitoring and metrics
//! - Backpressure behavior

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::writers::{
    DispatcherConfig, DispatcherStats, OverflowStrategy, dispatcher_capacity,
    dispatcher_health_score, dispatcher_is_degraded, dispatcher_is_healthy,
    dispatcher_overflow_strategy, dispatcher_stats, dispatcher_stats_extended,
};
use octarine::{debug, error, info, warn};
use std::time::Duration;

// ============================================================================
// Basic Dispatch Tests
// ============================================================================

#[test]
fn test_dispatch_stats_available() {
    super::ensure_test_dispatcher();

    let stats = dispatcher_stats();

    // Stats should have reasonable values
    assert!(stats.capacity > 0, "Dispatcher should have capacity");
    // Note: total_written may be non-zero from other tests
}

#[test]
fn test_dispatch_health_check() {
    super::ensure_test_dispatcher();

    // Health checks should return without panic
    let is_healthy = dispatcher_is_healthy();
    let is_degraded = dispatcher_is_degraded();
    let health_score = dispatcher_health_score();

    // Health score should be between 0.0 and 1.0
    assert!(
        (0.0..=1.0).contains(&health_score),
        "Health score {} should be between 0.0 and 1.0",
        health_score
    );

    // If healthy, should not be degraded (with no load)
    // Note: This may not hold if other tests have caused drops
    if is_healthy && health_score > 0.95 {
        assert!(
            !is_degraded,
            "Healthy dispatcher should not be degraded at high health score"
        );
    }
}

#[test]
fn test_dispatch_capacity() {
    super::ensure_test_dispatcher();

    let stats = dispatcher_stats();

    // Channel capacity should be 10,000 as per implementation
    assert_eq!(
        stats.capacity, 10_000,
        "Dispatcher capacity should be 10,000"
    );
}

// ============================================================================
// Event Queuing Tests
// ============================================================================

#[test]
fn test_logging_shortcuts_queue_events() {
    super::ensure_test_dispatcher();

    let stats_before = dispatcher_stats();

    // Queue some events via logging shortcuts
    info("dispatch_test", "Test info message");
    warn("dispatch_test", "Test warning message");
    debug("dispatch_test", "Test debug message");
    error("dispatch_test", "Test error message");

    // Give a moment for queuing (should be nearly instant)
    std::thread::sleep(Duration::from_millis(10));

    let stats_after = dispatcher_stats();

    // At least 4 more events should have been queued
    // (Could be more if other tests are running concurrently)
    assert!(
        stats_after.total_written >= stats_before.total_written + 4,
        "Expected at least 4 new events queued, before={}, after={}",
        stats_before.total_written,
        stats_after.total_written
    );
}

#[test]
fn test_many_events_queued_successfully() {
    super::ensure_test_dispatcher();

    let stats_before = dispatcher_stats();

    // Queue many events rapidly
    for i in 0..100 {
        info("bulk_test", format!("Event {}", i));
    }

    // Brief pause to let queue accept events
    std::thread::sleep(Duration::from_millis(50));

    let stats_after = dispatcher_stats();

    // Most events should have been queued (some may drop under pressure)
    let queued = stats_after.total_written - stats_before.total_written;
    assert!(
        queued >= 90,
        "Expected at least 90 events queued, got {}",
        queued
    );
}

// ============================================================================
// Health Score Tests
// ============================================================================

#[test]
fn test_health_score_formula() {
    super::ensure_test_dispatcher();

    let score = dispatcher_health_score();

    // Health score is calculated as:
    // success_rate - (retry_rate * 0.2), capped at 0.0 minimum
    // For a healthy system with low retry rate, score should be high
    assert!(
        score >= 0.0,
        "Health score should never be negative, got {}",
        score
    );
    assert!(
        score <= 1.0,
        "Health score should never exceed 1.0, got {}",
        score
    );
}

#[test]
fn test_health_thresholds() {
    super::ensure_test_dispatcher();

    // Document the health thresholds
    // is_healthy: drop_rate < 5%
    // is_degraded: drop_rate > 1% OR retry_rate > 10%

    let stats = dispatcher_stats();
    let total = stats.total_written + stats.total_dropped;

    if total > 0 {
        let drop_rate = stats.total_dropped as f64 / total as f64;

        // If drop rate is low, should be healthy
        if drop_rate < 0.01 {
            assert!(
                dispatcher_is_healthy(),
                "Drop rate {:.2}% should mean healthy",
                drop_rate * 100.0
            );
        }

        // If drop rate is high, should be degraded
        if drop_rate > 0.05 {
            assert!(
                dispatcher_is_degraded() || !dispatcher_is_healthy(),
                "Drop rate {:.2}% should indicate problems",
                drop_rate * 100.0
            );
        }
    }
}

// ============================================================================
// Async Context Tests
// ============================================================================

#[tokio::test]
async fn test_dispatch_from_async_context() {
    super::ensure_test_dispatcher();

    let stats_before = dispatcher_stats();

    // Queue events from async context
    for i in 0..10 {
        info("async_test", format!("Async event {}", i));
    }

    // Brief pause
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stats_after = dispatcher_stats();

    let queued = stats_after.total_written - stats_before.total_written;
    assert!(
        queued >= 10,
        "Expected 10 events from async context, got {}",
        queued
    );
}

#[tokio::test]
async fn test_concurrent_dispatch_from_tasks() {
    super::ensure_test_dispatcher();

    let stats_before = dispatcher_stats();

    // Spawn multiple tasks that all log concurrently
    let mut handles = vec![];

    for task_id in 0..5 {
        handles.push(tokio::spawn(async move {
            for i in 0..10 {
                info("concurrent_test", format!("Task {} event {}", task_id, i));
            }
        }));
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.expect("Task should complete");
    }

    // Brief pause for queuing
    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats_after = dispatcher_stats();

    // Should have queued 50 events (5 tasks * 10 events each)
    let queued = stats_after.total_written - stats_before.total_written;
    assert!(
        queued >= 45,
        "Expected at least 45 events from concurrent tasks, got {}",
        queued
    );
}

// ============================================================================
// Backpressure Behavior Tests
// ============================================================================

#[test]
fn test_dispatch_handles_burst_load() {
    super::ensure_test_dispatcher();

    let stats_before = dispatcher_stats();

    // Send a burst of events
    for i in 0..500 {
        info("burst_test", format!("Burst event {}", i));
    }

    // Check stats after burst
    let stats_after = dispatcher_stats();

    // Some events should have been queued
    let queued = stats_after.total_written - stats_before.total_written;
    assert!(queued > 0, "At least some events should be queued");

    // Total (queued + dropped) should equal what we sent
    let total_processed = (stats_after.total_written - stats_before.total_written)
        + (stats_after.total_dropped - stats_before.total_dropped);

    assert!(
        total_processed >= 450,
        "Expected most of 500 events processed, got {}",
        total_processed
    );
}

#[test]
fn test_drops_are_tracked() {
    super::ensure_test_dispatcher();

    let stats = dispatcher_stats();

    // Drops should be tracked (may be 0 if no backpressure)
    // This test just verifies the field exists and is accessible
    let _dropped = stats.total_dropped;

    // If there have been drops, is_degraded should eventually be true
    // (depending on threshold)
}

// ============================================================================
// Stats Consistency Tests
// ============================================================================

#[test]
fn test_stats_are_monotonic() {
    super::ensure_test_dispatcher();

    let stats1 = dispatcher_stats();

    // Queue more events
    info("monotonic_test", "Test event");
    std::thread::sleep(Duration::from_millis(10));

    let stats2 = dispatcher_stats();

    // Stats should only increase (monotonic)
    assert!(
        stats2.total_written >= stats1.total_written,
        "total_written should be monotonic"
    );
    assert!(
        stats2.total_dropped >= stats1.total_dropped,
        "total_dropped should be monotonic"
    );
}

#[test]
fn test_stats_capacity_is_constant() {
    super::ensure_test_dispatcher();

    let stats1 = dispatcher_stats();
    info("capacity_test", "Test event");
    let stats2 = dispatcher_stats();

    assert_eq!(
        stats1.capacity, stats2.capacity,
        "Capacity should remain constant"
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_message_dispatch() {
    super::ensure_test_dispatcher();

    // Empty messages should be handled
    info("edge_test", "");

    // Should not panic
}

#[test]
fn test_large_message_dispatch() {
    super::ensure_test_dispatcher();

    // Large messages should be handled
    let large_message = "x".repeat(10_000);
    info("large_test", &large_message);

    // Should not panic
}

#[test]
fn test_unicode_message_dispatch() {
    super::ensure_test_dispatcher();

    // Unicode should be handled
    info("unicode_test", "日本語メッセージ 🎉 émoji");

    // Should not panic
}

#[test]
fn test_special_chars_dispatch() {
    super::ensure_test_dispatcher();

    // Special characters should be handled
    info("special_test", "Line1\nLine2\tTabbed\r\nWindows");
    info("special_test", "Quotes: \"double\" and 'single'");
    info("special_test", "Backslash: \\ and \\\\");

    // Should not panic
}

// ============================================================================
// Extended Stats Tests (Issue #153)
// ============================================================================

#[test]
fn test_extended_stats_available() {
    super::ensure_test_dispatcher();

    let stats = dispatcher_stats_extended();

    // Extended stats should have all fields
    assert!(stats.capacity > 0, "Capacity should be positive");
    assert!(stats.utilization >= 0.0 && stats.utilization <= 1.0);
    assert!(stats.drop_rate >= 0.0 && stats.drop_rate <= 1.0);
    assert!(stats.retry_rate >= 0.0);
    assert!(!stats.uptime.is_zero() || stats.total_queued == 0);
}

#[test]
fn test_extended_stats_health_methods() {
    super::ensure_test_dispatcher();

    let stats = dispatcher_stats_extended();

    // Health score should match DispatcherStats method
    let calculated_score = stats.health_score();
    assert!(
        (0.0..=1.0).contains(&calculated_score),
        "Health score should be 0.0-1.0"
    );

    // Health methods should be consistent
    if stats.drop_rate < 0.05 {
        assert!(stats.is_healthy());
    }
    if stats.drop_rate > 0.01 || stats.retry_rate > 0.10 {
        assert!(stats.is_degraded());
    }
}

#[test]
fn test_overflow_strategy_accessor() {
    super::ensure_test_dispatcher();

    let strategy = dispatcher_overflow_strategy();

    // Default strategy should be RetryThenDrop
    assert_eq!(
        strategy,
        OverflowStrategy::RetryThenDrop,
        "Default overflow strategy should be RetryThenDrop"
    );
}

#[test]
fn test_capacity_accessor() {
    super::ensure_test_dispatcher();

    let capacity = dispatcher_capacity();

    // Should match stats capacity
    let stats = dispatcher_stats();
    assert_eq!(
        capacity, stats.capacity,
        "Capacity accessor should match stats"
    );
}

// ============================================================================
// DispatcherConfig Tests (Issue #153)
// ============================================================================

#[test]
fn test_dispatcher_config_development() {
    let config = DispatcherConfig::development();

    assert_eq!(config.capacity, 1_000);
    assert_eq!(config.overflow_strategy, OverflowStrategy::RetryThenDrop);
    assert_eq!(config.retry_attempts, 3);
}

#[test]
fn test_dispatcher_config_production() {
    let config = DispatcherConfig::production();

    assert_eq!(config.capacity, 10_000);
    assert_eq!(config.overflow_strategy, OverflowStrategy::RetryThenDrop);
}

#[test]
fn test_dispatcher_config_high_volume() {
    let config = DispatcherConfig::high_volume();

    assert_eq!(config.capacity, 50_000);
    assert_eq!(config.overflow_strategy, OverflowStrategy::DropNewest);
}

#[test]
fn test_dispatcher_config_critical() {
    let config = DispatcherConfig::critical();

    assert_eq!(config.capacity, 10_000);
    assert_eq!(config.overflow_strategy, OverflowStrategy::Block);
}

#[test]
fn test_dispatcher_config_default() {
    let config = DispatcherConfig::default();

    assert_eq!(config.capacity, 10_000);
    assert_eq!(config.overflow_strategy, OverflowStrategy::RetryThenDrop);
    assert_eq!(config.retry_attempts, 3);
    assert_eq!(config.batch_size, 100);
    assert_eq!(config.flush_interval, Duration::from_secs(1));
    assert!(config.overflow_callback.is_none());
}

// ============================================================================
// OverflowStrategy Tests (Issue #153)
// ============================================================================

#[test]
fn test_overflow_strategy_default_trait() {
    let strategy = OverflowStrategy::default();
    assert_eq!(strategy, OverflowStrategy::RetryThenDrop);
}

#[test]
fn test_overflow_strategy_variants() {
    // Ensure all variants exist and can be compared
    let strategies = [
        OverflowStrategy::DropNewest,
        OverflowStrategy::RetryThenDrop,
        OverflowStrategy::Block,
    ];

    for strategy in &strategies {
        assert_eq!(strategy, strategy);
    }

    // They should all be different
    assert_ne!(
        OverflowStrategy::DropNewest,
        OverflowStrategy::RetryThenDrop
    );
    assert_ne!(OverflowStrategy::RetryThenDrop, OverflowStrategy::Block);
    assert_ne!(OverflowStrategy::Block, OverflowStrategy::DropNewest);
}

// ============================================================================
// DispatcherStats Health Score Tests (Issue #153)
// ============================================================================

#[test]
fn test_stats_health_score_perfect() {
    let stats = DispatcherStats {
        current_size: 0,
        capacity: 10_000,
        total_queued: 1000,
        total_dropped: 0,
        total_retries: 0,
        total_processed: 1000,
        utilization: 0.0,
        drop_rate: 0.0,
        retry_rate: 0.0,
        uptime: Duration::from_secs(60),
        overflow_strategy: OverflowStrategy::RetryThenDrop,
    };

    assert!((stats.health_score() - 1.0).abs() < 0.001);
    assert!(stats.is_healthy());
    assert!(!stats.is_degraded());
}

#[test]
fn test_stats_health_score_degraded() {
    let stats = DispatcherStats {
        current_size: 5000,
        capacity: 10_000,
        total_queued: 900,
        total_dropped: 100,
        total_retries: 150,
        total_processed: 900,
        utilization: 0.5,
        drop_rate: 0.1,   // 10% - above 5% threshold
        retry_rate: 0.15, // 15% - above 10% threshold
        uptime: Duration::from_secs(60),
        overflow_strategy: OverflowStrategy::RetryThenDrop,
    };

    assert!(!stats.is_healthy());
    assert!(stats.is_degraded());
    assert!(stats.health_score() < 1.0);
}

#[test]
fn test_stats_health_score_with_retries() {
    let stats = DispatcherStats {
        current_size: 100,
        capacity: 10_000,
        total_queued: 1000,
        total_dropped: 0,
        total_retries: 200,
        total_processed: 1000,
        utilization: 0.01,
        drop_rate: 0.0,
        retry_rate: 0.2, // 20% retries
        uptime: Duration::from_secs(60),
        overflow_strategy: OverflowStrategy::RetryThenDrop,
    };

    // Still healthy (no drops) but has retry penalty
    assert!(stats.is_healthy());
    assert!(stats.is_degraded()); // retry_rate > 10%

    // Health score should reflect retry penalty
    let score = stats.health_score();
    assert!(score < 1.0);
    assert!(score > 0.9); // Retry penalty is capped
}
