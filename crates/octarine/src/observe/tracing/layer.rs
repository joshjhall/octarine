//! ObserveLayer - bridges tracing events to observe

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use uuid::Uuid;

use super::TracingConfig;
use crate::observe::types::{EventType, Severity};
use crate::primitives::runtime::{set_correlation_id, try_correlation_id};

/// A tracing Layer that forwards events to the observe system
///
/// This layer intercepts tracing events and span lifecycle events,
/// converting them to observe events and managing correlation IDs.
///
/// # Example
///
/// ```rust,no_run
/// use octarine::observe::tracing::{ObserveLayer, TracingConfig};
/// use tracing_subscriber::{layer::SubscriberExt, Registry};
///
/// let subscriber = Registry::default()
///     .with(ObserveLayer::new(TracingConfig::default()));
/// ```
pub struct ObserveLayer {
    config: TracingConfig,
    /// Maps span IDs to correlation IDs
    span_correlations: Arc<RwLock<HashMap<u64, Uuid>>>,
}

impl ObserveLayer {
    /// Create a new ObserveLayer with the given configuration
    pub fn new(config: TracingConfig) -> Self {
        Self {
            config,
            span_correlations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Convert tracing Level to observe Severity
    fn level_to_severity(level: &Level) -> Severity {
        match *level {
            Level::TRACE | Level::DEBUG => Severity::Debug,
            Level::INFO => Severity::Info,
            Level::WARN => Severity::Warning,
            Level::ERROR => Severity::Error,
        }
    }

    /// Convert tracing Level to observe EventType
    fn level_to_event_type(level: &Level) -> EventType {
        match *level {
            Level::TRACE | Level::DEBUG => EventType::Debug,
            Level::INFO => EventType::Info,
            Level::WARN => EventType::Warning,
            Level::ERROR => EventType::SystemError,
        }
    }

    /// Check if the event should be forwarded based on severity
    fn should_forward(&self, level: &Level) -> bool {
        let severity = Self::level_to_severity(level);
        severity >= self.config.min_level
    }

    /// Extract operation name from event fields or use default
    fn extract_operation(&self, event: &Event<'_>) -> String {
        let mut operation = None;

        event.record(&mut OperationVisitor {
            operation: &mut operation,
        });

        operation.unwrap_or_else(|| self.config.default_operation.clone())
    }

    /// Extract message and metadata from event
    fn extract_event_data(event: &Event<'_>) -> (String, HashMap<String, serde_json::Value>) {
        let mut visitor = EventDataVisitor::new();
        event.record(&mut visitor);
        (visitor.message, visitor.metadata)
    }

    /// Get or create correlation ID for a span
    fn get_span_correlation(&self, span_id: u64) -> Option<Uuid> {
        self.span_correlations.read().get(&span_id).copied()
    }

    /// Store correlation ID for a span
    fn set_span_correlation(&self, span_id: u64, correlation_id: Uuid) {
        self.span_correlations
            .write()
            .insert(span_id, correlation_id);
    }

    /// Remove correlation ID for a span
    fn remove_span_correlation(&self, span_id: u64) {
        self.span_correlations.write().remove(&span_id);
    }
}

impl<S> Layer<S> for ObserveLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
        if !self.config.capture_spans {
            return;
        }

        // Create or inherit correlation ID for this span
        let correlation_id = if self.config.propagate_correlation {
            // Try to extract from span attributes first
            let mut extracted_id = None;
            attrs.record(&mut CorrelationVisitor {
                correlation_id: &mut extracted_id,
            });

            // Use extracted ID, or inherit from current context, or create new
            extracted_id
                .or_else(try_correlation_id)
                .unwrap_or_else(Uuid::new_v4)
        } else {
            Uuid::new_v4()
        };

        self.set_span_correlation(id.into_u64(), correlation_id);
    }

    fn on_enter(&self, id: &Id, _ctx: Context<'_, S>) {
        if !self.config.propagate_correlation {
            return;
        }

        // Set the correlation ID for the current thread/task
        if let Some(correlation_id) = self.get_span_correlation(id.into_u64()) {
            set_correlation_id(correlation_id);
        }
    }

    fn on_exit(&self, _id: &Id, _ctx: Context<'_, S>) {
        // Note: We don't clear the correlation ID on exit because
        // it should persist until explicitly cleared or the request ends
    }

    fn on_close(&self, id: Id, _ctx: Context<'_, S>) {
        self.remove_span_correlation(id.into_u64());
    }

    fn on_record(&self, _span: &Id, _values: &Record<'_>, _ctx: Context<'_, S>) {
        // Could update span metadata here if needed
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();

        // Check if we should forward this event
        if !self.should_forward(metadata.level()) {
            return;
        }

        // Extract operation and message
        let operation = self.extract_operation(event);
        let (message, mut extra_metadata) = Self::extract_event_data(event);

        // Get current span's correlation ID if available
        if self.config.propagate_correlation
            && let Some(span) = ctx.current_span().id()
            && let Some(correlation_id) = self.get_span_correlation(span.into_u64())
        {
            set_correlation_id(correlation_id);
        }

        // Add target to metadata if configured
        if self.config.capture_target {
            extra_metadata.insert(
                "target".to_string(),
                serde_json::Value::String(metadata.target().to_string()),
            );
        }

        // Add span attributes if configured
        if self.config.include_span_attributes
            && let Some(span) = ctx.current_span().id()
            && let Some(span_ref) = ctx.span(span)
        {
            extra_metadata.insert(
                "span_name".to_string(),
                serde_json::Value::String(span_ref.name().to_string()),
            );
        }

        // Forward to observe
        let event_type = Self::level_to_event_type(metadata.level());
        let severity = Self::level_to_severity(metadata.level());

        // Create and dispatch the observe event
        dispatch_to_observe(&operation, &message, event_type, severity, extra_metadata);
    }
}

/// Visitor to extract operation name from event fields
struct OperationVisitor<'a> {
    operation: &'a mut Option<String>,
}

impl tracing::field::Visit for OperationVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "operation" || field.name() == "op" {
            *self.operation = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "operation" || field.name() == "op" {
            *self.operation = Some(format!("{:?}", value));
        }
    }
}

/// Visitor to extract correlation ID from span attributes
struct CorrelationVisitor<'a> {
    correlation_id: &'a mut Option<Uuid>,
}

impl tracing::field::Visit for CorrelationVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if (field.name() == "correlation_id" || field.name() == "trace_id")
            && let Ok(id) = Uuid::parse_str(value)
        {
            *self.correlation_id = Some(id);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "correlation_id" || field.name() == "trace_id" {
            let s = format!("{:?}", value);
            if let Ok(id) = Uuid::parse_str(&s) {
                *self.correlation_id = Some(id);
            }
        }
    }
}

/// Visitor to extract message and metadata from events
struct EventDataVisitor {
    message: String,
    metadata: HashMap<String, serde_json::Value>,
}

impl EventDataVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            metadata: HashMap::new(),
        }
    }
}

impl tracing::field::Visit for EventDataVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" || field.name() == "msg" {
            self.message = value.to_string();
        } else if field.name() != "operation" && field.name() != "op" {
            self.metadata.insert(
                field.name().to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.metadata
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.metadata
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.metadata
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.metadata
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" || field.name() == "msg" {
            self.message = format!("{:?}", value);
        } else if field.name() != "operation" && field.name() != "op" {
            self.metadata.insert(
                field.name().to_string(),
                serde_json::Value::String(format!("{:?}", value)),
            );
        }
    }
}

/// Dispatch an event to the observe system
///
/// This function creates an observe event and dispatches it through
/// the normal observe pipeline (including PII scanning).
fn dispatch_to_observe(
    operation: &str,
    message: &str,
    event_type: EventType,
    severity: Severity,
    metadata: HashMap<String, serde_json::Value>,
) {
    use crate::observe::types::Event;
    use crate::observe::writers;

    let mut event = Event::new(event_type, message);
    event.severity = severity;
    event.context.operation = operation.to_string();
    event.metadata = metadata;

    writers::dispatch(event);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_level_to_severity() {
        assert_eq!(
            ObserveLayer::level_to_severity(&Level::TRACE),
            Severity::Debug
        );
        assert_eq!(
            ObserveLayer::level_to_severity(&Level::DEBUG),
            Severity::Debug
        );
        assert_eq!(
            ObserveLayer::level_to_severity(&Level::INFO),
            Severity::Info
        );
        assert_eq!(
            ObserveLayer::level_to_severity(&Level::WARN),
            Severity::Warning
        );
        assert_eq!(
            ObserveLayer::level_to_severity(&Level::ERROR),
            Severity::Error
        );
    }

    #[test]
    fn test_level_to_event_type() {
        assert_eq!(
            ObserveLayer::level_to_event_type(&Level::DEBUG),
            EventType::Debug
        );
        assert_eq!(
            ObserveLayer::level_to_event_type(&Level::INFO),
            EventType::Info
        );
        assert_eq!(
            ObserveLayer::level_to_event_type(&Level::WARN),
            EventType::Warning
        );
        assert_eq!(
            ObserveLayer::level_to_event_type(&Level::ERROR),
            EventType::SystemError
        );
    }

    #[test]
    fn test_should_forward() {
        let layer = ObserveLayer::new(TracingConfig::default().min_level(Severity::Info));

        assert!(!layer.should_forward(&Level::DEBUG));
        assert!(layer.should_forward(&Level::INFO));
        assert!(layer.should_forward(&Level::WARN));
        assert!(layer.should_forward(&Level::ERROR));
    }

    #[test]
    fn test_span_correlation_storage() {
        let layer = ObserveLayer::new(TracingConfig::default());
        let span_id = 12345u64;
        let correlation_id = Uuid::new_v4();

        // Initially empty
        assert!(layer.get_span_correlation(span_id).is_none());

        // Store
        layer.set_span_correlation(span_id, correlation_id);
        assert_eq!(layer.get_span_correlation(span_id), Some(correlation_id));

        // Remove
        layer.remove_span_correlation(span_id);
        assert!(layer.get_span_correlation(span_id).is_none());
    }
}
