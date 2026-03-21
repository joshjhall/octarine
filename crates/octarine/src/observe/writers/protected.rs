//! Circuit breaker protected writers
//!
//! Wraps writers with circuit breaker protection for fault tolerance.
//! Also dispatches events to all registered writers in the registry.

use crate::observe::Result;
use crate::observe::types::Event;
use crate::primitives::runtime::r#async::{CircuitBreaker, CircuitBreakerConfig};
use std::sync::Arc;

use super::console::ConsoleWriter;
use super::dispatch_to_writers_sync;

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

    /// Write event synchronously (for batch processing)
    ///
    /// Dispatches to console and all registered writers.
    /// This bypasses the circuit breaker since batch processing already
    /// handles failures at a higher level.
    pub fn write_sync(&self, event: &Event) {
        // Always write to console for immediate feedback
        self.console.write_sync(event);

        // Dispatch to all registered writers
        dispatch_to_writers_sync(event);
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
        let writer = ProtectedWriter::new();
        let event = Event::new(EventType::Debug, "sync test");

        // Should not panic
        writer.write_sync(&event);
        assert!(writer.is_healthy());
    }
}
