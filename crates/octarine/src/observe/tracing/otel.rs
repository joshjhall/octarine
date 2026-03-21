//! OpenTelemetry integration for distributed tracing
//!
//! This module provides integration with OpenTelemetry for industry-standard
//! distributed tracing. It enables automatic trace context propagation across
//! services and compatibility with major observability platforms.
//!
//! # Feature Flag
//!
//! This module requires the `otel` feature flag:
//!
//! ```toml
//! [dependencies]
//! rust-core = { version = "0.2", features = ["otel"] }
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use octarine::observe::tracing::otel::{init_otel, OtelConfig, shutdown_otel};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize OpenTelemetry with OTLP exporter
//!     let config = OtelConfig::new("my-service")
//!         .with_otlp_endpoint("http://localhost:4317");
//!     init_otel(config)?;
//!
//!     // Your application code...
//!     // All observe events will be exported as spans
//!
//!     // Shutdown cleanly
//!     shutdown_otel();
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use opentelemetry::trace::{
    Span as SpanTrait, SpanContext, SpanId, SpanKind, Status, TraceContextExt, TraceFlags, TraceId,
    TraceState, Tracer,
};
use opentelemetry::{Context, KeyValue, global};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use uuid::Uuid;

use crate::observe::types::{Event, EventType, Severity};

/// Global tracer provider for OpenTelemetry
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Configuration for OpenTelemetry integration
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// Service name for tracing
    pub service_name: String,
    /// OTLP endpoint (default: http://localhost:4317)
    pub otlp_endpoint: String,
    /// Additional resource attributes
    pub resource_attributes: HashMap<String, String>,
    /// Export timeout
    pub export_timeout: Duration,
    /// Whether to export to OTLP
    pub export_enabled: bool,
}

impl OtelConfig {
    /// Create a new OtelConfig with the given service name
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            otlp_endpoint: "http://localhost:4317".to_string(),
            resource_attributes: HashMap::new(),
            export_timeout: Duration::from_secs(10),
            export_enabled: true,
        }
    }

    /// Set the OTLP endpoint
    pub fn with_otlp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_endpoint = endpoint.into();
        self
    }

    /// Add a resource attribute
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.resource_attributes.insert(key.into(), value.into());
        self
    }

    /// Set the export timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.export_timeout = timeout;
        self
    }

    /// Disable OTLP export (useful for testing)
    pub fn without_export(mut self) -> Self {
        self.export_enabled = false;
        self
    }

    /// Create a development configuration (no export, just local tracing)
    pub fn development(service_name: impl Into<String>) -> Self {
        Self::new(service_name).without_export()
    }

    /// Create a production configuration with standard settings
    pub fn production(service_name: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self::new(service_name)
            .with_otlp_endpoint(endpoint)
            .with_attribute("deployment.environment", "production")
    }
}

/// Error type for OpenTelemetry operations
#[derive(Debug, thiserror::Error)]
pub enum OtelError {
    /// Failed to initialize the tracer
    #[error("Failed to initialize OpenTelemetry tracer: {0}")]
    InitError(String),
    /// Tracer not initialized
    #[error("OpenTelemetry tracer not initialized - call init_otel first")]
    NotInitialized,
    /// Export failed
    #[error("Failed to export spans: {0}")]
    ExportError(String),
}

impl From<OtelError> for crate::observe::Problem {
    fn from(err: OtelError) -> Self {
        match err {
            OtelError::InitError(msg) => Self::config(format!("OpenTelemetry init: {msg}")),
            OtelError::NotInitialized => Self::config("OpenTelemetry not initialized"),
            OtelError::ExportError(msg) => Self::operation_failed(format!("span export: {msg}")),
        }
    }
}

/// Initialize OpenTelemetry with the given configuration
///
/// This sets up the global tracer provider with an OTLP exporter.
/// Call this once at application startup.
///
/// # Errors
///
/// Returns an error if initialization fails or if already initialized.
pub fn init_otel(config: OtelConfig) -> Result<(), OtelError> {
    // Build resource using builder pattern (0.31+ API)
    let mut resource_builder = Resource::builder_empty();
    resource_builder = resource_builder.with_service_name(config.service_name.clone());

    for (key, value) in &config.resource_attributes {
        resource_builder =
            resource_builder.with_attribute(KeyValue::new(key.clone(), value.clone()));
    }

    let resource = resource_builder.build();

    // Build tracer provider
    let provider = if config.export_enabled {
        // Create OTLP exporter (0.31+ API with grpc-tonic feature)
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&config.otlp_endpoint)
            .with_timeout(config.export_timeout)
            .build()
            .map_err(|e| OtelError::InitError(e.to_string()))?;

        // Note: 0.31+ no longer requires async runtime for batch exporter
        SdkTracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(exporter)
            .build()
    } else {
        // No export - just create a basic provider
        SdkTracerProvider::builder().with_resource(resource).build()
    };

    // Set as global provider
    global::set_tracer_provider(provider.clone());

    TRACER_PROVIDER
        .set(provider)
        .map_err(|_| OtelError::InitError("OpenTelemetry already initialized".to_string()))?;

    Ok(())
}

/// Shutdown OpenTelemetry and flush any pending spans
///
/// Call this before application exit to ensure all spans are exported.
pub fn shutdown_otel() {
    // In 0.31+, we shutdown via the provider directly if available
    if let Some(provider) = TRACER_PROVIDER.get() {
        let _ = provider.shutdown();
    }
}

/// Get the global tracer for creating spans
fn get_tracer() -> impl Tracer {
    global::tracer("rust-core-observe")
}

/// Convert a UUID to an OpenTelemetry TraceId
pub fn uuid_to_trace_id(uuid: Uuid) -> TraceId {
    TraceId::from_bytes(uuid.as_bytes().to_owned())
}

/// Convert a UUID to an OpenTelemetry SpanId (uses lower 8 bytes)
pub fn uuid_to_span_id(uuid: Uuid) -> SpanId {
    let bytes = uuid.as_bytes();
    let mut span_bytes = [0u8; 8];
    span_bytes.copy_from_slice(&bytes[8..16]);
    SpanId::from_bytes(span_bytes)
}

/// Convert an OpenTelemetry TraceId to a UUID
pub fn trace_id_to_uuid(trace_id: TraceId) -> Uuid {
    Uuid::from_bytes(trace_id.to_bytes())
}

/// Convert observe Severity to OpenTelemetry Status
fn severity_to_status(severity: Severity) -> Status {
    match severity {
        Severity::Critical | Severity::Error => Status::error(""),
        _ => Status::Ok,
    }
}

/// Convert observe EventType to OpenTelemetry SpanKind
fn event_type_to_span_kind(event_type: EventType) -> SpanKind {
    match event_type {
        // Authentication events are typically server-side
        EventType::AuthenticationSuccess
        | EventType::AuthenticationError
        | EventType::LoginSuccess
        | EventType::LoginFailure => SpanKind::Server,
        // Resource operations are internal
        EventType::ResourceCreated | EventType::ResourceUpdated | EventType::ResourceDeleted => {
            SpanKind::Internal
        }
        // Default to internal for other event types
        _ => SpanKind::Internal,
    }
}

/// Create an OpenTelemetry span from an observe Event
///
/// This converts observe events into OpenTelemetry spans, enabling
/// integration with OTLP-compatible observability platforms.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::observe::tracing::otel::export_event;
/// use octarine::observe::Event;
///
/// let event = Event::info("Processing request");
/// export_event(&event);
/// ```
pub fn export_event(event: &Event) {
    let tracer = get_tracer();

    // Build span attributes from event
    let mut attributes = vec![
        KeyValue::new("observe.event_type", format!("{:?}", event.event_type)),
        KeyValue::new("observe.severity", format!("{:?}", event.severity)),
        KeyValue::new("observe.operation", event.context.operation.clone()),
    ];

    // Add context attributes
    if let Some(ref tenant_id) = event.context.tenant_id {
        attributes.push(KeyValue::new("tenant.id", tenant_id.to_string()));
    }
    if let Some(ref user_id) = event.context.user_id {
        attributes.push(KeyValue::new("user.id", user_id.to_string()));
    }
    if let Some(ref session_id) = event.context.session_id {
        attributes.push(KeyValue::new("session.id", session_id.clone()));
    }
    if !event.context.module_path.is_empty() {
        attributes.push(KeyValue::new(
            "code.namespace",
            event.context.module_path.clone(),
        ));
    }
    if !event.context.file.is_empty() {
        attributes.push(KeyValue::new("code.filepath", event.context.file.clone()));
    }
    if event.context.line > 0 {
        attributes.push(KeyValue::new("code.lineno", event.context.line as i64));
    }

    // Add metadata as attributes
    for (key, value) in &event.metadata {
        let attr_value = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => value.to_string(),
        };
        attributes.push(KeyValue::new(
            format!("observe.metadata.{}", key),
            attr_value,
        ));
    }

    // Create parent context if we have a correlation ID
    let parent_context = if event.context.correlation_id != Uuid::nil() {
        let trace_id = uuid_to_trace_id(event.context.correlation_id);
        let span_id = uuid_to_span_id(Uuid::new_v4()); // Generate new span ID

        let span_context = SpanContext::new(
            trace_id,
            span_id,
            TraceFlags::SAMPLED,
            false,
            TraceState::default(),
        );

        Context::current().with_remote_span_context(span_context)
    } else {
        Context::current()
    };

    // Create the span
    let mut span = tracer
        .span_builder(event.context.operation.clone())
        .with_kind(event_type_to_span_kind(event.event_type))
        .with_start_time(SystemTime::from(event.timestamp))
        .with_attributes(attributes)
        .start_with_context(&tracer, &parent_context);

    // Set span status based on severity
    SpanTrait::set_status(&mut span, severity_to_status(event.severity));

    // Add the message as an event on the span
    SpanTrait::add_event(
        &mut span,
        event.message.clone(),
        vec![KeyValue::new(
            "observe.original_message",
            event.message.clone(),
        )],
    );

    // Span is automatically ended when dropped
    drop(span);
}

/// OpenTelemetry span exporter that wraps observe events
///
/// This writer exports observe events as OpenTelemetry spans,
/// enabling integration with OTLP-compatible backends like
/// Jaeger, Zipkin, or cloud observability platforms.
pub struct OtelExporter {
    /// Whether export is enabled
    enabled: bool,
}

impl OtelExporter {
    /// Create a new OtelExporter
    ///
    /// Note: You must call `init_otel` before creating an exporter.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Create a disabled exporter (for testing)
    pub fn disabled() -> Self {
        Self { enabled: false }
    }

    /// Export an observe event as an OpenTelemetry span
    pub fn export(&self, event: &Event) {
        if self.enabled {
            export_event(event);
        }
    }
}

impl Default for OtelExporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Context propagation helpers for HTTP headers
///
/// These functions help propagate trace context across service boundaries
/// using W3C Trace Context format.
pub mod propagation {
    use super::*;
    use crate::observe::tracing::propagation::{
        HeaderLike, HeaderLikeMut, TraceContext, extract_from_headers, inject_to_headers,
    };

    /// Extract OpenTelemetry context from HTTP headers
    ///
    /// This uses the existing W3C Trace Context extraction from the
    /// propagation module and converts it to an OpenTelemetry Context.
    pub fn extract_context<H: HeaderLike>(headers: &H) -> Context {
        if let Some(correlation_id) = extract_from_headers(headers) {
            let trace_id = uuid_to_trace_id(correlation_id);
            let span_id = uuid_to_span_id(Uuid::new_v4());

            let span_context = SpanContext::new(
                trace_id,
                span_id,
                TraceFlags::SAMPLED,
                true, // Remote context
                TraceState::default(),
            );

            Context::current().with_remote_span_context(span_context)
        } else {
            Context::current()
        }
    }

    /// Inject OpenTelemetry context into HTTP headers
    ///
    /// This extracts the current trace context and injects it using
    /// the W3C Trace Context format.
    pub fn inject_context<H: HeaderLikeMut>(headers: &mut H) {
        let context = Context::current();
        let span_ref = context.span();
        let span_context = span_ref.span_context();

        if span_context.is_valid() {
            let correlation_id = trace_id_to_uuid(span_context.trace_id());
            inject_to_headers(headers, correlation_id);
        }
    }

    /// Run a closure with the given trace context
    ///
    /// This sets up the OpenTelemetry context for the duration of the closure,
    /// ensuring all spans created within are properly parented.
    pub fn with_context<F, R>(trace_ctx: &TraceContext, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let trace_id = uuid_to_trace_id(trace_ctx.correlation_id);
        let span_id = if let Some(parent) = trace_ctx.parent_span_id {
            uuid_to_span_id(parent)
        } else {
            uuid_to_span_id(Uuid::new_v4())
        };

        let span_context = SpanContext::new(
            trace_id,
            span_id,
            TraceFlags::SAMPLED,
            false,
            TraceState::default(),
        );

        let context = Context::current().with_remote_span_context(span_context);
        let _guard = context.attach();

        f()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_otel_config_new() {
        let config = OtelConfig::new("test-service");
        assert_eq!(config.service_name, "test-service");
        assert_eq!(config.otlp_endpoint, "http://localhost:4317");
        assert!(config.export_enabled);
    }

    #[test]
    fn test_otel_config_builder() {
        let config = OtelConfig::new("my-service")
            .with_otlp_endpoint("http://otel:4317")
            .with_attribute("env", "test")
            .with_timeout(Duration::from_secs(30))
            .without_export();

        assert_eq!(config.service_name, "my-service");
        assert_eq!(config.otlp_endpoint, "http://otel:4317");
        assert_eq!(
            config.resource_attributes.get("env"),
            Some(&"test".to_string())
        );
        assert_eq!(config.export_timeout, Duration::from_secs(30));
        assert!(!config.export_enabled);
    }

    #[test]
    fn test_otel_config_presets() {
        let dev = OtelConfig::development("dev-service");
        assert!(!dev.export_enabled);

        let prod = OtelConfig::production("prod-service", "http://prod:4317");
        assert!(prod.export_enabled);
        assert_eq!(prod.otlp_endpoint, "http://prod:4317");
        assert_eq!(
            prod.resource_attributes.get("deployment.environment"),
            Some(&"production".to_string())
        );
    }

    #[test]
    fn test_uuid_to_trace_id_roundtrip() {
        let original = Uuid::new_v4();
        let trace_id = uuid_to_trace_id(original);
        let recovered = trace_id_to_uuid(trace_id);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_uuid_to_span_id() {
        let uuid = Uuid::new_v4();
        let span_id = uuid_to_span_id(uuid);
        // SpanId should be 8 bytes (64 bits)
        assert_ne!(span_id, SpanId::INVALID);
    }

    #[test]
    fn test_severity_to_status() {
        assert!(matches!(
            severity_to_status(Severity::Critical),
            Status::Error { .. }
        ));
        assert!(matches!(
            severity_to_status(Severity::Error),
            Status::Error { .. }
        ));
        assert!(matches!(severity_to_status(Severity::Warning), Status::Ok));
        assert!(matches!(severity_to_status(Severity::Info), Status::Ok));
        assert!(matches!(severity_to_status(Severity::Debug), Status::Ok));
    }

    #[test]
    fn test_event_type_to_span_kind() {
        assert!(matches!(
            event_type_to_span_kind(EventType::AuthenticationSuccess),
            SpanKind::Server
        ));
        assert!(matches!(
            event_type_to_span_kind(EventType::LoginSuccess),
            SpanKind::Server
        ));
        assert!(matches!(
            event_type_to_span_kind(EventType::Info),
            SpanKind::Internal
        ));
        assert!(matches!(
            event_type_to_span_kind(EventType::ResourceCreated),
            SpanKind::Internal
        ));
    }

    #[test]
    fn test_otel_exporter_creation() {
        let exporter = OtelExporter::new();
        assert!(exporter.enabled);

        let disabled = OtelExporter::disabled();
        assert!(!disabled.enabled);
    }
}
