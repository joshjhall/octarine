//! Integration tests for end-to-end writer dispatch through the async
//! dispatcher.
//!
//! Regression coverage for issue #210: prior to the fix,
//! `dispatch_to_writers_sync` built a nested tokio runtime inside the
//! dispatcher's own runtime and the resulting panic was swallowed by
//! `let _ = ...`, silently dropping events for every registered writer
//! except the always-synchronous console.
//!
//! Cargo runs these tests in parallel inside a single process, sharing
//! the global `WRITER_REGISTRY` and `EVENT_DISPATCHER`. Tests use unique
//! per-test writer names and unique event message markers, and assertions
//! filter captured events by marker — never by absolute count — so two
//! tests that fan out through the dispatcher cannot disturb each other.

#![allow(clippy::panic, clippy::expect_used)]

use async_trait::async_trait;
use octarine::observe::writers::{
    MemoryWriter, Writer, WriterError, WriterHealthStatus, disable_writer, dispatch,
    register_writer, unregister_writer,
};
use octarine::observe::{Event, EventType};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::{Instant, sleep};

/// Poll `probe` up to `deadline`, checking every `interval`. Returns
/// `true` as soon as the probe succeeds. Avoids fixed-duration sleeps so
/// the test is resilient under CI scheduling jitter.
async fn poll_until<F: FnMut() -> bool>(
    deadline: Duration,
    interval: Duration,
    mut probe: F,
) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if probe() {
            return true;
        }
        sleep(interval).await;
    }
    probe()
}

/// Count how many stored events match a message marker. Using markers
/// rather than absolute counts lets tests run in parallel on the shared
/// global dispatcher without disturbing each other.
fn count_with_marker(writer: &MemoryWriter, marker: &str) -> usize {
    writer
        .all_events()
        .iter()
        .filter(|e| e.message.contains(marker))
        .count()
}

/// Named proxy around a shared `MemoryWriter` so multiple concurrent tests
/// can register distinct capture writers against the global registry.
struct CaptureWriter {
    inner: Arc<MemoryWriter>,
    name: &'static str,
}

#[async_trait]
impl Writer for CaptureWriter {
    async fn write(&self, event: &Event) -> Result<(), WriterError> {
        self.inner.write(event).await
    }

    async fn flush(&self) -> Result<(), WriterError> {
        self.inner.flush().await
    }

    fn health_check(&self) -> WriterHealthStatus {
        self.inner.health_check()
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Writer that always fails. Used to verify a failing writer does not
/// block dispatch to other writers.
struct AlwaysFailingWriter {
    name: &'static str,
    failures: Arc<AtomicUsize>,
}

#[async_trait]
impl Writer for AlwaysFailingWriter {
    async fn write(&self, _event: &Event) -> Result<(), WriterError> {
        self.failures.fetch_add(1, Ordering::Relaxed);
        Err(WriterError::Other("simulated failure".into()))
    }

    async fn flush(&self) -> Result<(), WriterError> {
        Ok(())
    }

    fn health_check(&self) -> WriterHealthStatus {
        WriterHealthStatus::Healthy
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn registered_writer_receives_dispatched_event() {
    let capture = Arc::new(MemoryWriter::with_capacity(64));
    let name = "writer_dispatch_receives";
    let marker = "WD_RECEIVES_v1_7f4a";
    register_writer(Box::new(CaptureWriter {
        inner: Arc::clone(&capture),
        name,
    }));

    dispatch(Event::new(EventType::Info, marker));

    let received = poll_until(Duration::from_secs(2), Duration::from_millis(10), || {
        count_with_marker(&capture, marker) >= 1
    })
    .await;

    unregister_writer(name);

    assert!(
        received,
        "registered writer never received the dispatched event (issue #210 regression)"
    );
    assert_eq!(
        count_with_marker(&capture, marker),
        1,
        "expected exactly one event with marker {marker}"
    );
}

#[tokio::test]
async fn multiple_writers_all_receive_event() {
    let a = Arc::new(MemoryWriter::with_capacity(64));
    let b = Arc::new(MemoryWriter::with_capacity(64));
    let name_a = "writer_dispatch_multi_a";
    let name_b = "writer_dispatch_multi_b";
    let marker = "WD_FANOUT_v1_a913";

    register_writer(Box::new(CaptureWriter {
        inner: Arc::clone(&a),
        name: name_a,
    }));
    register_writer(Box::new(CaptureWriter {
        inner: Arc::clone(&b),
        name: name_b,
    }));

    dispatch(Event::new(EventType::Info, marker));

    let both = poll_until(Duration::from_secs(2), Duration::from_millis(10), || {
        count_with_marker(&a, marker) >= 1 && count_with_marker(&b, marker) >= 1
    })
    .await;

    unregister_writer(name_a);
    unregister_writer(name_b);

    assert!(both, "both registered writers should receive the event");
    assert_eq!(count_with_marker(&a, marker), 1);
    assert_eq!(count_with_marker(&b, marker), 1);
}

#[tokio::test]
async fn failing_writer_does_not_block_others() {
    let failures = Arc::new(AtomicUsize::new(0));
    let good = Arc::new(MemoryWriter::with_capacity(64));
    let failing_name = "writer_dispatch_failing";
    let good_name = "writer_dispatch_good_peer";
    let marker = "WD_FAILING_v1_c027";

    register_writer(Box::new(AlwaysFailingWriter {
        name: failing_name,
        failures: Arc::clone(&failures),
    }));
    register_writer(Box::new(CaptureWriter {
        inner: Arc::clone(&good),
        name: good_name,
    }));

    dispatch(Event::new(EventType::Info, marker));

    let good_received = poll_until(Duration::from_secs(5), Duration::from_millis(50), || {
        count_with_marker(&good, marker) >= 1
    })
    .await;

    unregister_writer(failing_name);
    unregister_writer(good_name);

    assert!(
        good_received,
        "the healthy writer must receive the event even when a peer writer fails"
    );
    assert!(
        failures.load(Ordering::Relaxed) >= 1,
        "the failing writer should have been invoked at least once"
    );
}

#[tokio::test]
async fn disabled_writer_receives_nothing() {
    let capture = Arc::new(MemoryWriter::with_capacity(64));
    let name = "writer_dispatch_disabled";
    let marker = "WD_DISABLED_v1_5b88";

    register_writer(Box::new(CaptureWriter {
        inner: Arc::clone(&capture),
        name,
    }));
    disable_writer(name);

    dispatch(Event::new(EventType::Info, marker));

    // Use a second marker event on a second writer to know when the
    // dispatcher has had a fair chance to process this test's submission.
    // Polling the original capture until a deadline would always succeed
    // by timing out; we want a positive signal that dispatch flushed.
    let probe = Arc::new(MemoryWriter::with_capacity(64));
    let probe_name = "writer_dispatch_disabled_probe";
    let probe_marker = "WD_DISABLED_PROBE_v1_5b88";
    register_writer(Box::new(CaptureWriter {
        inner: Arc::clone(&probe),
        name: probe_name,
    }));
    dispatch(Event::new(EventType::Info, probe_marker));

    let probe_received = poll_until(Duration::from_secs(2), Duration::from_millis(10), || {
        count_with_marker(&probe, probe_marker) >= 1
    })
    .await;

    let disabled_count = count_with_marker(&capture, marker);

    unregister_writer(name);
    unregister_writer(probe_name);

    assert!(
        probe_received,
        "probe writer should receive its event, confirming dispatcher flushed"
    );
    assert_eq!(
        disabled_count, 0,
        "disabled writer should not receive any events"
    );
}
