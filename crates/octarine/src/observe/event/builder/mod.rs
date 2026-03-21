//! Event builder for configurable event creation
//!
//! Provides a builder pattern for constructing and dispatching events.
//! This follows the three-layer pattern where the builder orchestrates
//! but doesn't implement business logic - it delegates to the dispatch implementation.

use crate::observe::EventContext;
use std::collections::HashMap;

// No shortcuts at builder level - they're at the event level

// Extension modules that add methods to EventBuilder
mod dispatch;

use crate::observe::pii::PiiScanResult;

/// Main event builder for constructing and dispatching events
#[derive(Debug, Clone)]
pub(in crate::observe) struct EventBuilder {
    // Event configuration
    pub(super) message: String,
    pub(super) context: Option<EventContext>,
    // Event metadata
    pub(super) metadata: HashMap<String, serde_json::Value>,
    // PII redaction control
    pub(super) skip_pii_redaction: bool,
    // PII scan results (populated during message processing)
    pub(super) pii_result: Option<PiiScanResult>,
}

impl EventBuilder {
    /// Create a new event builder with a message
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            context: None,
            metadata: HashMap::new(),
            skip_pii_redaction: false,
            pii_result: None,
        }
    }

    /// Set the event context
    pub fn with_context(mut self, context: EventContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Set metadata from a HashMap
    pub fn with_metadata_map(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Add a single metadata entry
    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Skip PII redaction for this event (use with caution)
    ///
    /// By default, all event messages are scanned for PII and automatically redacted
    /// based on the environment profile. Use this method when:
    /// - The message is known to contain no PII
    /// - You need full verbatim output for debugging (non-production only)
    /// - The message has already been sanitized upstream
    ///
    /// # Security Warning
    ///
    /// Skipping PII redaction may expose sensitive data in logs. Only use this
    /// in controlled environments or when you have verified the message is safe.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::event::EventBuilder;
    ///
    /// // Safe: message is known to contain no PII
    /// EventBuilder::new("Server started successfully")
    ///     .skip_pii_redaction()
    ///     .info();
    ///
    /// // Unsafe: may expose email in production
    /// EventBuilder::new("User registered: user@example.com")
    ///     .skip_pii_redaction()  // ❌ Avoid this!
    ///     .info();
    /// ```
    pub fn skip_pii_redaction(mut self) -> Self {
        self.skip_pii_redaction = true;
        self
    }
}

impl Default for EventBuilder {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Note: These tests verify PII redaction through the public pii module API
    // EventBuilder integration is tested through dispatch methods

    #[test]
    fn test_builder_creation() {
        let builder = EventBuilder::new("test message");
        assert_eq!(builder.message, "test message");
        assert!(!builder.skip_pii_redaction);
        assert!(builder.pii_result.is_none());
    }

    #[test]
    fn test_skip_pii_redaction_flag() {
        let builder = EventBuilder::new("test").skip_pii_redaction();
        assert!(builder.skip_pii_redaction);
    }

    #[test]
    fn test_with_context() {
        use crate::observe::EventContext;
        let context = EventContext::default();
        let builder = EventBuilder::new("test").with_context(context.clone());
        assert!(builder.context.is_some());
    }
}
