//! End-to-end I/O tests for the `ObserveLayer` tracing bridge.
//!
//! The existing `tracing_integration.rs` covers config and header
//! propagation. This file drives real tracing events and spans *through* the
//! layer with a live `tracing_subscriber` and asserts on what actually
//! reaches the observe writer pipeline — the `on_event` / `on_new_span` /
//! visitor code paths that config tests never touch.
//!
//! Delivery is asynchronous (the layer forwards through the global async
//! dispatcher to registered writers), so every assertion polls until the
//! signal arrives rather than sleeping a fixed amount — see
//! `octarine-test-resilience`. Tests filter captured events by a unique
//! per-test marker so they remain correct whether run process-per-test
//! (nextest) or many-per-process (`cargo test`).

#![allow(clippy::panic, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::{Instant, sleep};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, Registry};

use octarine::observe::tracing::{ObserveLayer, TracingConfig};
use octarine::observe::writers::{
    MemoryWriter, Writer, WriterError, WriterHealthStatus, register_writer, unregister_writer,
};
use octarine::observe::{Event, EventType, Severity};

const POLL_DEADLINE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

async fn poll_until<F: FnMut() -> bool>(mut probe: F) -> bool {
    let start = Instant::now();
    while start.elapsed() < POLL_DEADLINE {
        if probe() {
            return true;
        }
        sleep(POLL_INTERVAL).await;
    }
    probe()
}

/// Named proxy around a shared `MemoryWriter` so concurrent tests can register
/// distinct capture writers against the global registry.
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

    // Accept everything so Debug-level events are not filtered before capture.
    fn severity_filter(&self) -> octarine::observe::writers::SeverityFilter {
        octarine::observe::writers::SeverityFilter::all()
    }
}

/// RAII guard that unregisters a writer from the process-global registry on
/// drop, so cleanup happens even if an assertion panics mid-test. The global
/// `WRITER_REGISTRY` is shared with sibling tests; leaking a writer on a
/// failure path would change behavior for whatever runs next in the same
/// process (e.g. under plain `cargo test`). Mirrors the cleanup-before-assert
/// safety of `writer_dispatch.rs`, but panic-safe.
struct WriterGuard {
    name: &'static str,
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        unregister_writer(self.name);
    }
}

/// Register `capture` under `name` and return a guard that removes it on drop.
fn register_capture(name: &'static str, capture: &Arc<MemoryWriter>) -> WriterGuard {
    register_writer(Box::new(CaptureWriter {
        inner: Arc::clone(capture),
        name,
    }));
    WriterGuard { name }
}

fn events_with_marker(writer: &MemoryWriter, marker: &str) -> Vec<Event> {
    writer
        .all_events()
        .into_iter()
        .filter(|e| e.message.contains(marker))
        .collect()
}

/// Build a subscriber whose only layer is an `ObserveLayer` with `config`,
/// restricted to the given max level so unrelated framework spam does not
/// flow through the global dispatcher.
fn subscriber_with(config: TracingConfig) -> impl tracing::Subscriber + Send + Sync {
    Registry::default().with(ObserveLayer::new(config).with_filter(
        tracing_subscriber::filter::LevelFilter::from_level(Level::TRACE),
    ))
}

#[tokio::test]
async fn event_is_forwarded_with_message_and_metadata() {
    super::ensure_test_dispatcher();

    let capture = Arc::new(MemoryWriter::with_capacity(256));
    let name = "tracing_layer_forward";
    let marker = "TL_FORWARD_9c1a";
    // Guard unregisters on drop, so a panicking assertion below cannot leak the
    // writer into the process-global registry.
    let _guard = register_capture(name, &capture);

    let subscriber = subscriber_with(TracingConfig::default().min_level(Severity::Debug));

    // Emit an event with a custom field; the EventDataVisitor should surface
    // `message` as the event message and the extra field as metadata.
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(user_count = 42, "{}", marker);
    });

    let found = poll_until(|| !events_with_marker(&capture, marker).is_empty()).await;
    assert!(found, "event should reach the writer via the layer");

    let events = events_with_marker(&capture, marker);
    let event = events.first().expect("one captured event");
    // INFO maps to Info severity / Info event type.
    assert_eq!(event.severity, Severity::Info);
    assert!(matches!(event.event_type, EventType::Info));
    // The i64 field must be carried through as metadata.
    let meta = event
        .metadata
        .get("user_count")
        .expect("user_count metadata present");
    assert_eq!(meta.as_i64(), Some(42));
}

#[tokio::test]
async fn level_maps_to_severity_and_event_type() {
    super::ensure_test_dispatcher();

    let capture = Arc::new(MemoryWriter::with_capacity(256));
    let name = "tracing_layer_levels";
    let marker = "TL_LEVELS_4f7d";
    let _guard = register_capture(name, &capture);

    let subscriber = subscriber_with(TracingConfig::default().min_level(Severity::Debug));
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!("{} warn", marker);
        tracing::error!("{} error", marker);
    });

    let ready = poll_until(|| events_with_marker(&capture, marker).len() >= 2).await;
    assert!(ready, "both events should be forwarded");

    let events = events_with_marker(&capture, marker);
    let warn = events
        .iter()
        .find(|e| e.message.contains("warn"))
        .expect("warn event");
    let error = events
        .iter()
        .find(|e| e.message.contains("error"))
        .expect("error event");

    // WARN -> Warning severity + Warning type; ERROR -> Error severity +
    // SystemError type. These mappings are the layer's contract.
    assert_eq!(warn.severity, Severity::Warning);
    assert!(matches!(warn.event_type, EventType::Warning));
    assert_eq!(error.severity, Severity::Error);
    assert!(matches!(error.event_type, EventType::SystemError));
}

#[tokio::test]
async fn below_min_level_is_dropped() {
    super::ensure_test_dispatcher();

    let capture = Arc::new(MemoryWriter::with_capacity(256));
    let name = "tracing_layer_minlevel";
    let below = "TL_BELOW_5b2e";
    let above = "TL_ABOVE_5b2e";
    let _guard = register_capture(name, &capture);

    // min_level = Warning: an INFO event must be filtered out by
    // `should_forward` (in `ObserveLayer::on_event`) *before* it is ever queued
    // on the dispatcher; a WARN event must pass.
    let subscriber = subscriber_with(TracingConfig::default().min_level(Severity::Warning));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!("{}", below);
        tracing::warn!("{}", above);
    });

    // Wait until the above-threshold event arrives...
    let ready = poll_until(|| !events_with_marker(&capture, above).is_empty()).await;
    assert!(ready, "warn event should be forwarded");

    // ...then the below-threshold one must be absent. The INFO event is dropped
    // at the layer before dispatch, so it never enters the queue — there is no
    // ordering race to wait out; if it were going to appear it already would.
    assert!(
        events_with_marker(&capture, below).is_empty(),
        "info event below min_level must not be forwarded"
    );
}

#[tokio::test]
async fn operation_field_sets_event_operation() {
    super::ensure_test_dispatcher();

    let capture = Arc::new(MemoryWriter::with_capacity(256));
    let name = "tracing_layer_operation";
    let marker = "TL_OP_7a3c";
    let _guard = register_capture(name, &capture);

    let subscriber = subscriber_with(TracingConfig::default().min_level(Severity::Debug));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(operation = "checkout", "{}", marker);
    });

    let ready = poll_until(|| !events_with_marker(&capture, marker).is_empty()).await;
    assert!(ready, "event should be forwarded");

    let events = events_with_marker(&capture, marker);
    let event = events.first().expect("captured event");
    // The `operation` field is extracted by OperationVisitor and must set the
    // event's operation (rather than leaking into generic metadata).
    assert_eq!(event.context.operation, "checkout");
    assert!(
        !event.metadata.contains_key("operation"),
        "operation should not be duplicated into metadata"
    );
}
