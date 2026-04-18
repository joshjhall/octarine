//! Circuit breaker protected writers
//!
//! Wraps writers with circuit breaker protection for fault tolerance.
//! Also dispatches events to all registered writers in the registry.

use crate::observe::Result;
use crate::observe::types::Event;
use crate::primitives::runtime::r#async::{CircuitBreaker, CircuitBreakerConfig};
use std::sync::Arc;

use super::console::ConsoleWriter;
use super::dispatch_to_writers;

/// A writer protected by a circuit breaker
///
/// Dispatches events to:
/// 1. The console writer (always, for immediate feedback)
/// 2. All registered writers in `WRITER_REGISTRY`
pub(super) struct ProtectedWriter {
    console: ConsoleWriter,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl ProtectedWriter {
    /// Create a new protected writer with default circuit breaker config
    pub fn new() -> Self {
        // Use high-availability preset: quick to open, needs high success to close
        // This is appropriate for writers which should be reliable
        let config = CircuitBreakerConfig::high_availability();

        Self {
            console: ConsoleWriter::new(),
            circuit_breaker: Arc::new(CircuitBreaker::with_config(config)),
        }
    }

    /// Write an event through the circuit breaker
    pub async fn write(&self, event: &Event) -> Result<()> {
        let console = &self.console;
        let event_clone = event.clone();

        self.circuit_breaker
            .execute(async move {
                console.write_sync(&event_clone);
                Ok(())
            })
            .await
    }

    /// Dispatch an event through the full writer pipeline.
    ///
    /// Writes to the console synchronously for immediate feedback, then
    /// awaits dispatch to all registered writers. Must be called from
    /// within a tokio runtime — the dispatcher background thread runs one.
    /// Bypasses the circuit breaker since batch processing already handles
    /// failures at a higher level.
    pub async fn write_event(&self, event: &Event) {
        self.console.write_sync(event);
        dispatch_to_writers(event).await;
    }

    /// Console-only fallback write.
    ///
    /// Used only when the dispatcher cannot build a tokio runtime
    /// (`async_dispatch::EventDispatcher::new`). In that degraded state
    /// there is no runtime to host async writers, so we write to stderr
    /// via `ConsoleWriter` and skip registry dispatch entirely.
    /// Production paths go through [`Self::write_event`].
    pub fn write_sync(&self, event: &Event) {
        self.console.write_sync(event);
    }

    /// Get circuit breaker state for monitoring
    pub fn is_healthy(&self) -> bool {
        self.circuit_breaker.can_proceed()
    }
}

impl Default for ProtectedWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::types::{Event, EventType};

    #[tokio::test]
    async fn test_protected_writer() {
        let writer = ProtectedWriter::new();
        let event = Event::new(EventType::Debug, "test event");

        // Should succeed
        let result = writer.write(&event).await;
        assert!(result.is_ok());
        assert!(writer.is_healthy());
    }

    #[test]
    fn test_protected_writer_sync() {
        // `write_sync` is the console-only fallback used when no tokio
        // runtime is available. It must not panic and must not require
        // the registry to be initialised.
        let writer = ProtectedWriter::new();
        let event = Event::new(EventType::Debug, "sync test");

        writer.write_sync(&event);
        assert!(writer.is_healthy());
    }

    #[tokio::test]
    async fn test_protected_writer_event_dispatches_to_registry() {
        use crate::observe::writers::{MemoryWriter, register_writer, unregister_writer};
        use std::sync::Arc;

        // The writer registry is global and may receive concurrent events
        // from other tests. Use a unique marker in the event message so
        // assertions remain stable under `-j4` parallel execution.
        let marker = "PROTECTED_DISPATCH_MARKER_c4f21";
        let capture = Arc::new(MemoryWriter::with_capacity(64));
        register_writer(Box::new(MemoryWriterHandle {
            inner: Arc::clone(&capture),
            name: "protected_dispatch_capture",
        }));

        let writer = ProtectedWriter::new();
        writer
            .write_event(&Event::new(EventType::Info, marker))
            .await;

        let received = capture
            .all_events()
            .iter()
            .filter(|e| e.message.contains(marker))
            .count();

        unregister_writer("protected_dispatch_capture");

        assert_eq!(
            received, 1,
            "registered writer should receive the marker event exactly once"
        );
    }

    // Named proxy around an external `MemoryWriter` so multiple tests can
    // register their own capture without colliding on the shared registry.
    struct MemoryWriterHandle {
        inner: std::sync::Arc<crate::observe::writers::MemoryWriter>,
        name: &'static str,
    }

    #[async_trait::async_trait]
    impl crate::observe::writers::Writer for MemoryWriterHandle {
        async fn write(
            &self,
            event: &Event,
        ) -> std::result::Result<(), crate::observe::writers::WriterError> {
            self.inner.write(event).await
        }

        async fn flush(&self) -> std::result::Result<(), crate::observe::writers::WriterError> {
            self.inner.flush().await
        }

        fn health_check(&self) -> crate::observe::writers::WriterHealthStatus {
            self.inner.health_check()
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }
}
