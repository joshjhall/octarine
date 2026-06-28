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
//! octarine = { version = "0.3", features = ["otel"] }
//! ```
//!
//! # Example
//!
//! Pre-existing example - ignored at compile until adapted.
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
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use uuid::Uuid;

use crate::observe::ProblemExt;
use crate::observe::types::{Event, EventType, Severity};

/// Global tracer provider for OpenTelemetry
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// OTLP transport protocol for the span exporter.
///
/// The default is [`OtlpProtocol::Grpc`], preserving the original behavior.
/// The HTTP variants require the `otel-http` cargo feature; selecting one
/// without that feature compiled returns an [`OtelError::InitError`] at
/// [`init_otel`] time rather than failing to compile, so gRPC-only builds are
/// unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OtlpProtocol {
    /// OTLP over gRPC (tonic transport). Default; listens on port 4317 by
    /// convention.
    #[default]
    Grpc,
    /// OTLP over HTTP with binary protobuf payloads. Port 4318 by convention.
    ///
    /// Requires the `otel-http` feature.
    HttpBinary,
    /// OTLP over HTTP with JSON-encoded payloads. Port 4318 by convention.
    ///
    /// Requires the `otel-http` feature.
    HttpJson,
}

/// Configuration for OpenTelemetry integration
///
/// `Debug` is implemented manually to redact header values: `headers` may carry
/// auth tokens (bearer tokens, API keys), which must never reach logs, spans, or
/// error chains in plaintext.
#[derive(Clone)]
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
    /// OTLP transport protocol (default: gRPC)
    pub protocol: OtlpProtocol,
    /// Headers forwarded on every export request (e.g. auth tokens).
    ///
    /// Private so every header passes through [`with_header`](Self::with_header)
    /// — this keeps the values out of `Debug` output and leaves room to validate
    /// on insert. Names (not values) are inspectable via
    /// [`header_names`](Self::header_names). Applied as gRPC metadata for
    /// [`OtlpProtocol::Grpc`] and as HTTP headers for the HTTP transports.
    headers: HashMap<String, String>,
}

impl std::fmt::Debug for OtelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact header values — they may be credentials. Names are kept so the
        // configured set is still visible for debugging.
        let redacted: HashMap<&str, &str> = self
            .headers
            .keys()
            .map(|k| (k.as_str(), "[REDACTED]"))
            .collect();
        f.debug_struct("OtelConfig")
            .field("service_name", &self.service_name)
            .field("otlp_endpoint", &self.otlp_endpoint)
            .field("resource_attributes", &self.resource_attributes)
            .field("export_timeout", &self.export_timeout)
            .field("export_enabled", &self.export_enabled)
            .field("protocol", &self.protocol)
            .field("headers", &redacted)
            .finish()
    }
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
            protocol: OtlpProtocol::default(),
            headers: HashMap::new(),
        }
    }

    /// Set the OTLP endpoint
    pub fn with_otlp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_endpoint = endpoint.into();
        self
    }

    /// Select the OTLP transport protocol.
    ///
    /// Defaults to [`OtlpProtocol::Grpc`]. Use [`OtlpProtocol::HttpBinary`] or
    /// [`OtlpProtocol::HttpJson`] to target OTLP/HTTP receivers; both require
    /// the `otel-http` feature.
    ///
    /// For the HTTP transports the endpoint is used verbatim — include the full
    /// per-signal path (e.g. `/v1/traces`). The `/v1/traces` suffix is only
    /// auto-appended when configuring via the `OTEL_EXPORTER_OTLP_ENDPOINT`
    /// environment variable, not via [`with_otlp_endpoint`](Self::with_otlp_endpoint).
    ///
    /// # Example
    ///
    /// Grafana Cloud OTLP (HTTP/protobuf) with a bearer token. Ignored at
    /// compile time — uses placeholder credentials and a live external endpoint.
    ///
    /// ```rust,ignore
    /// use octarine::observe::tracing::{OtelConfig, OtlpProtocol};
    ///
    /// let config = OtelConfig::new("my-service")
    ///     .with_otlp_endpoint("https://otlp-gateway-prod.grafana.net/otlp/v1/traces")
    ///     .with_otlp_protocol(OtlpProtocol::HttpBinary)
    ///     .with_header("Authorization", "Basic <base64-instance-id:token>");
    /// ```
    ///
    /// Honeycomb OTLP/HTTP. Ignored at compile time — uses a placeholder API
    /// key and a live external endpoint.
    ///
    /// ```rust,ignore
    /// use octarine::observe::tracing::{OtelConfig, OtlpProtocol};
    ///
    /// let config = OtelConfig::new("my-service")
    ///     .with_otlp_endpoint("https://api.honeycomb.io/v1/traces")
    ///     .with_otlp_protocol(OtlpProtocol::HttpBinary)
    ///     .with_header("x-honeycomb-team", "<api-key>");
    /// ```
    pub fn with_otlp_protocol(mut self, protocol: OtlpProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Add a header forwarded on every export request.
    ///
    /// Sent as gRPC metadata for the gRPC transport and as an HTTP header for
    /// the HTTP transports. Typically used for auth tokens, e.g.
    /// `Authorization: Api-Token ...`.
    ///
    /// This is an infallible setter (per the project's builder convention).
    /// Header names/values are validated once, for both transports, at
    /// [`init_otel`] time — an invalid name or value (e.g. containing CRLF or
    /// other control characters) surfaces a single [`OtelError::InitError`]
    /// there rather than being silently dropped here. Names are lower-cased so
    /// case-variant duplicates (`Authorization` vs `authorization`) collapse to
    /// one entry instead of colliding nondeterministically at export time.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(key.into().to_ascii_lowercase(), value.into());
        self
    }

    /// Iterate the configured export header names (not values).
    ///
    /// Values are intentionally not exposed — they may be credentials, and
    /// [`Debug`](OtelConfig) redacts them. Use this to inspect which headers are
    /// configured without risking a credential leak.
    pub fn header_names(&self) -> impl Iterator<Item = &str> {
        self.headers.keys().map(String::as_str)
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

/// Build an OTLP span exporter for the configured transport.
///
/// Branches between the gRPC (tonic) and HTTP (reqwest) backends. Headers are
/// forwarded as gRPC metadata or HTTP headers respectively. The HTTP arms
/// require the `otel-http` feature; without it, selecting an HTTP protocol
/// returns an [`OtelError::InitError`] describing the missing feature.
fn build_exporter(config: &OtelConfig) -> Result<opentelemetry_otlp::SpanExporter, OtelError> {
    // Validate every header once, for both transports, before building. This is
    // the single point where an invalid name/value (CRLF, control chars) is
    // reported — the HTTP path forwards the raw map, so without this it would
    // validate later with a less actionable error.
    validate_headers(&config.headers)?;

    match config.protocol {
        OtlpProtocol::Grpc => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&config.otlp_endpoint)
                .with_timeout(config.export_timeout);

            if !config.headers.is_empty() {
                builder = builder.with_metadata(grpc_metadata(&config.headers)?);
            }

            builder
                .build()
                .map_err(|e| OtelError::InitError(e.to_string()))
        }
        OtlpProtocol::HttpBinary | OtlpProtocol::HttpJson => build_http_exporter(config),
    }
}

/// Validate that every header name and value is a legal HTTP header (RFC 7230).
///
/// Rejects CRLF/control-character injection. Applied uniformly to both
/// transports so an invalid auth header fails loudly at init rather than being
/// silently dropped or sent malformed.
fn validate_headers(headers: &HashMap<String, String>) -> Result<(), OtelError> {
    for (key, value) in headers {
        http::header::HeaderName::from_bytes(key.as_bytes())
            .map_err(|e| OtelError::InitError(format!("invalid header name '{key}': {e}")))?;
        http::header::HeaderValue::from_str(value)
            .map_err(|e| OtelError::InitError(format!("invalid header value for '{key}': {e}")))?;
    }
    Ok(())
}

/// Convert a (pre-validated) header map into gRPC metadata for the tonic
/// transport. Uses `append` so distinct entries are all preserved; names are
/// already lower-cased by [`OtelConfig::with_header`], so case-variant
/// duplicates were collapsed at insert time.
fn grpc_metadata(
    headers: &HashMap<String, String>,
) -> Result<opentelemetry_otlp::tonic_types::metadata::MetadataMap, OtelError> {
    let mut header_map = http::HeaderMap::new();
    for (key, value) in headers {
        let name = http::header::HeaderName::from_bytes(key.as_bytes())
            .map_err(|e| OtelError::InitError(format!("invalid header name '{key}': {e}")))?;
        let val = http::header::HeaderValue::from_str(value)
            .map_err(|e| OtelError::InitError(format!("invalid header value for '{key}': {e}")))?;
        header_map.append(name, val);
    }
    Ok(opentelemetry_otlp::tonic_types::metadata::MetadataMap::from_headers(header_map))
}

/// Build the OTLP/HTTP span exporter (binary protobuf or JSON).
///
/// Only compiled with the `otel-http` feature. The fallback below returns an
/// actionable error when an HTTP protocol is requested in a gRPC-only build.
#[cfg(feature = "otel-http")]
fn build_http_exporter(config: &OtelConfig) -> Result<opentelemetry_otlp::SpanExporter, OtelError> {
    use opentelemetry_otlp::{Protocol, WithHttpConfig};

    let protocol = match config.protocol {
        OtlpProtocol::HttpBinary => Protocol::HttpBinary,
        OtlpProtocol::HttpJson => Protocol::HttpJson,
        // The caller (`build_exporter`) routes gRPC to the tonic path, so this
        // is unreachable in practice. Return an error rather than silently
        // mapping to HttpBinary, so any future routing change fails loudly
        // instead of sending spans over the wrong transport.
        OtlpProtocol::Grpc => {
            return Err(OtelError::InitError(
                "internal error: gRPC protocol routed to the HTTP exporter".to_string(),
            ));
        }
    };

    let mut builder = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(&config.otlp_endpoint)
        .with_timeout(config.export_timeout)
        .with_protocol(protocol);

    if !config.headers.is_empty() {
        builder = builder.with_headers(config.headers.clone());
    }

    builder
        .build()
        .map_err(|e| OtelError::InitError(e.to_string()))
}

/// Fallback when the `otel-http` feature is not enabled.
#[cfg(not(feature = "otel-http"))]
fn build_http_exporter(
    _config: &OtelConfig,
) -> Result<opentelemetry_otlp::SpanExporter, OtelError> {
    Err(OtelError::InitError(
        "OTLP/HTTP transport requested but the `otel-http` feature is not enabled. \
         Rebuild with `--features otel-http` to use HttpBinary or HttpJson."
            .to_string(),
    ))
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
        let exporter = build_exporter(&config)?;

        // Note: 0.31+ no longer requires async runtime for batch exporter
        SdkTracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(exporter)
            .build()
    } else {
        // No export - just create a basic provider
        SdkTracerProvider::builder().with_resource(resource).build()
    };

    // Claim the one-shot init slot FIRST. Only set the global provider once the
    // guard succeeds, so a double-init (or startup race) cannot replace the live
    // global provider while orphaning the original in the OnceLock unshutdown.
    TRACER_PROVIDER
        .set(provider.clone())
        .map_err(|_| OtelError::InitError("OpenTelemetry already initialized".to_string()))?;

    global::set_tracer_provider(provider);

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
    global::tracer("octarine-observe")
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
/// Pre-existing example - ignored at compile until adapted.
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
    fn test_otel_config_default_protocol_is_grpc() {
        // Default transport must stay gRPC — no breaking change for callers.
        let config = OtelConfig::new("svc");
        assert_eq!(config.protocol, OtlpProtocol::Grpc);
        assert!(config.headers.is_empty());
    }

    #[test]
    fn test_otel_config_protocol_and_headers() {
        let config = OtelConfig::new("svc")
            .with_otlp_protocol(OtlpProtocol::HttpBinary)
            .with_header("Authorization", "Api-Token abc")
            .with_header("x-tenant", "acme");

        assert_eq!(config.protocol, OtlpProtocol::HttpBinary);
        // Names are lower-cased on insert.
        assert_eq!(
            config.headers.get("authorization"),
            Some(&"Api-Token abc".to_string())
        );
        assert_eq!(config.headers.get("x-tenant"), Some(&"acme".to_string()));
    }

    #[test]
    fn test_with_header_lowercases_names_collapsing_case_variants() {
        // Case-variant duplicates must collapse to one entry (last wins),
        // matching gRPC/HTTP case-insensitive header semantics.
        let config = OtelConfig::new("svc")
            .with_header("Authorization", "first")
            .with_header("authorization", "second");
        assert_eq!(config.headers.len(), 1);
        assert_eq!(
            config.headers.get("authorization"),
            Some(&"second".to_string())
        );
    }

    #[test]
    fn test_validate_headers_rejects_crlf_injection() {
        // CRLF/control chars are rejected at init time (validate_headers), not
        // silently dropped by the infallible builder.
        let mut headers = HashMap::new();
        headers.insert("x-bad".to_string(), "value\r\ninjected".to_string());
        let err = validate_headers(&headers).expect_err("CRLF value must error");
        assert!(matches!(err, OtelError::InitError(_)));

        let mut bad_name = HashMap::new();
        bad_name.insert("x-bad\nname".to_string(), "v".to_string());
        assert!(matches!(
            validate_headers(&bad_name),
            Err(OtelError::InitError(_))
        ));
    }

    #[test]
    fn test_validate_headers_accepts_valid() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Api-Token abc".to_string());
        assert!(validate_headers(&headers).is_ok());
    }

    #[test]
    fn test_debug_redacts_header_values() {
        let config = OtelConfig::new("svc").with_header("Authorization", "Api-Token super-secret");
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("super-secret"),
            "header values must be redacted in Debug output: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
        // Names remain visible for debuggability (lower-cased on insert).
        assert!(rendered.contains("authorization"));
    }

    #[test]
    fn test_header_names_exposes_names_not_values() {
        let config = OtelConfig::new("svc")
            .with_header("Authorization", "Api-Token secret")
            .with_header("x-tenant", "acme");
        let mut names: Vec<&str> = config.header_names().collect();
        names.sort_unstable();
        assert_eq!(names, vec!["authorization", "x-tenant"]);
    }

    #[test]
    fn test_otlp_protocol_default_trait() {
        assert_eq!(OtlpProtocol::default(), OtlpProtocol::Grpc);
    }

    #[cfg(not(feature = "otel-http"))]
    #[test]
    fn test_http_protocol_without_feature_errors() {
        // Selecting an HTTP transport without the `otel-http` feature must fail
        // at init time with an actionable error, not a compile break.
        let config = OtelConfig::new("svc").with_otlp_protocol(OtlpProtocol::HttpBinary);
        let err = build_exporter(&config).expect_err("HTTP without otel-http must error");
        assert!(matches!(err, OtelError::InitError(_)));
        assert!(err.to_string().contains("otel-http"));
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
    fn test_grpc_metadata_converts_headers() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Api-Token abc".to_string());
        headers.insert("x-tenant".to_string(), "acme".to_string());

        let metadata = grpc_metadata(&headers).expect("valid headers convert");
        assert_eq!(
            metadata.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Api-Token abc")
        );
        assert_eq!(
            metadata.get("x-tenant").and_then(|v| v.to_str().ok()),
            Some("acme")
        );
    }

    #[test]
    fn test_grpc_metadata_rejects_invalid_header_name() {
        let mut headers = HashMap::new();
        // Spaces are not valid in HTTP header names.
        headers.insert("bad name".to_string(), "value".to_string());
        let err = grpc_metadata(&headers).expect_err("invalid name must error");
        assert!(matches!(err, OtelError::InitError(_)));
    }

    #[test]
    fn test_grpc_metadata_rejects_invalid_header_value() {
        let mut headers = HashMap::new();
        // ASCII control characters are not valid in HTTP header values.
        headers.insert("x-api-key".to_string(), "\u{1}invalid".to_string());
        let err = grpc_metadata(&headers).expect_err("control char in value must error");
        assert!(matches!(err, OtelError::InitError(_)));
        assert!(err.to_string().contains("x-api-key"));
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
