//! HTTP header propagation for distributed tracing
//!
//! Supports multiple header formats:
//! - X-Correlation-ID (custom)
//! - X-Request-ID (common)
//! - traceparent (W3C Trace Context)

use std::collections::HashMap;
use uuid::Uuid;

/// Trace context for distributed tracing
///
/// Contains the correlation ID and optional parent span information
/// that should be propagated across service boundaries.
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Correlation ID (also known as trace ID)
    pub correlation_id: Uuid,
    /// Parent span ID for hierarchical tracing
    pub parent_span_id: Option<Uuid>,
    /// Additional baggage items to propagate
    pub baggage: HashMap<String, String>,
}

impl TraceContext {
    /// Create a new TraceContext with a fresh correlation ID
    pub fn new() -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            parent_span_id: None,
            baggage: HashMap::new(),
        }
    }

    /// Create a TraceContext with a specific correlation ID
    pub fn with_correlation_id(correlation_id: Uuid) -> Self {
        Self {
            correlation_id,
            parent_span_id: None,
            baggage: HashMap::new(),
        }
    }

    /// Set the parent span ID
    pub fn with_parent(mut self, parent_span_id: Uuid) -> Self {
        self.parent_span_id = Some(parent_span_id);
        self
    }

    /// Add a baggage item
    pub fn with_baggage(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.baggage.insert(key.into(), value.into());
        self
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard header names for trace context propagation
pub mod headers {
    /// Custom correlation ID header
    pub const X_CORRELATION_ID: &str = "X-Correlation-ID";
    /// Common request ID header
    pub const X_REQUEST_ID: &str = "X-Request-ID";
    /// W3C Trace Context header
    pub const TRACEPARENT: &str = "traceparent";
    /// W3C Trace State header
    pub const TRACESTATE: &str = "tracestate";
    /// Baggage header (W3C)
    pub const BAGGAGE: &str = "baggage";
}

/// Extract a correlation ID from HTTP headers
///
/// Tries headers in this order:
/// 1. X-Correlation-ID
/// 2. X-Request-ID
/// 3. traceparent (W3C format)
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
/// use octarine::observe::tracing::extract_from_headers;
///
/// let mut headers = HashMap::new();
/// headers.insert("X-Correlation-ID".to_string(), "550e8400-e29b-41d4-a716-446655440000".to_string());
///
/// let id = extract_from_headers(&headers);
/// assert!(id.is_some());
/// ```
pub fn extract_from_headers<H>(headers: &H) -> Option<Uuid>
where
    H: HeaderLike,
{
    // Try X-Correlation-ID first
    if let Some(value) = headers.get_header(headers::X_CORRELATION_ID)
        && let Ok(id) = Uuid::parse_str(&value)
    {
        return Some(id);
    }

    // Try X-Request-ID
    if let Some(value) = headers.get_header(headers::X_REQUEST_ID)
        && let Ok(id) = Uuid::parse_str(&value)
    {
        return Some(id);
    }

    // Try W3C traceparent
    if let Some(value) = headers.get_header(headers::TRACEPARENT)
        && let Some(id) = parse_traceparent(&value)
    {
        return Some(id);
    }

    None
}

/// Extract full trace context from HTTP headers
///
/// Returns a TraceContext with correlation ID, parent span ID,
/// and any baggage items.
pub fn extract_correlation_id<H>(headers: &H) -> TraceContext
where
    H: HeaderLike,
{
    let correlation_id = extract_from_headers(headers).unwrap_or_else(Uuid::new_v4);
    let parent_span_id = extract_parent_span(headers);
    let baggage = extract_baggage(headers);

    TraceContext {
        correlation_id,
        parent_span_id,
        baggage,
    }
}

/// Inject correlation ID into HTTP headers
///
/// Adds multiple headers for compatibility:
/// - X-Correlation-ID
/// - X-Request-ID
/// - traceparent (W3C format)
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
/// use uuid::Uuid;
/// use octarine::observe::tracing::inject_to_headers;
///
/// let mut headers = HashMap::new();
/// let correlation_id = Uuid::new_v4();
///
/// inject_to_headers(&mut headers, correlation_id);
///
/// assert!(headers.contains_key("X-Correlation-ID"));
/// ```
pub fn inject_to_headers<H>(headers: &mut H, correlation_id: Uuid)
where
    H: HeaderLikeMut,
{
    let id_string = correlation_id.to_string();

    // Set custom header
    headers.set_header(headers::X_CORRELATION_ID, &id_string);

    // Set common header
    headers.set_header(headers::X_REQUEST_ID, &id_string);

    // Set W3C traceparent (version 00, trace_id, span_id, flags)
    // We use the correlation_id for both trace_id and span_id for simplicity
    let trace_id = format!("{:032x}", correlation_id.as_u128());
    let span_id = &trace_id[16..32]; // Use second half as span_id
    let traceparent = format!("00-{}-{}-01", trace_id, span_id);
    headers.set_header(headers::TRACEPARENT, &traceparent);
}

/// Inject full trace context into HTTP headers
pub fn inject_correlation_id<H>(headers: &mut H, context: &TraceContext)
where
    H: HeaderLikeMut,
{
    inject_to_headers(headers, context.correlation_id);

    // Inject baggage if present
    if !context.baggage.is_empty() {
        let baggage: Vec<String> = context
            .baggage
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        headers.set_header(headers::BAGGAGE, &baggage.join(","));
    }
}

/// Parse W3C traceparent header format
///
/// Format: {version}-{trace-id}-{parent-id}-{flags}
/// Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
fn parse_traceparent(value: &str) -> Option<Uuid> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() >= 2 {
        // trace-id is the second part (32 hex chars)
        let trace_id = parts.get(1)?;
        if trace_id.len() == 32 {
            // Convert to UUID format
            let uuid_str = format!(
                "{}-{}-{}-{}-{}",
                &trace_id[0..8],
                &trace_id[8..12],
                &trace_id[12..16],
                &trace_id[16..20],
                &trace_id[20..32]
            );
            return Uuid::parse_str(&uuid_str).ok();
        }
    }
    None
}

/// Extract parent span ID from headers
fn extract_parent_span<H>(headers: &H) -> Option<Uuid>
where
    H: HeaderLike,
{
    if let Some(value) = headers.get_header(headers::TRACEPARENT) {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() >= 3 {
            // parent-id is the third part (16 hex chars)
            let parent_id = parts.get(2)?;
            if parent_id.len() == 16 {
                // Pad to UUID format (use zeros for first half)
                let uuid_str = format!(
                    "00000000-0000-0000-{}-{}",
                    &parent_id[0..4],
                    &parent_id[4..16]
                );
                return Uuid::parse_str(&uuid_str).ok();
            }
        }
    }
    None
}

/// Extract baggage items from headers
fn extract_baggage<H>(headers: &H) -> HashMap<String, String>
where
    H: HeaderLike,
{
    let mut baggage = HashMap::new();

    if let Some(value) = headers.get_header(headers::BAGGAGE) {
        for item in value.split(',') {
            if let Some((key, val)) = item.split_once('=') {
                baggage.insert(key.trim().to_string(), val.trim().to_string());
            }
        }
    }

    baggage
}

/// Trait for reading headers from various HTTP libraries
pub trait HeaderLike {
    /// Get a header value by name (case-insensitive)
    fn get_header(&self, name: &str) -> Option<String>;
}

/// Trait for writing headers to various HTTP libraries
pub trait HeaderLikeMut {
    /// Set a header value
    fn set_header(&mut self, name: &str, value: &str);
}

// Implementation for HashMap<String, String>
impl HeaderLike for HashMap<String, String> {
    fn get_header(&self, name: &str) -> Option<String> {
        // Try exact match first
        if let Some(v) = self.get(name) {
            return Some(v.clone());
        }
        // Try case-insensitive
        let lower = name.to_lowercase();
        for (k, v) in self {
            if k.to_lowercase() == lower {
                return Some(v.clone());
            }
        }
        None
    }
}

impl HeaderLikeMut for HashMap<String, String> {
    fn set_header(&mut self, name: &str, value: &str) {
        self.insert(name.to_string(), value.to_string());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_trace_context_new() {
        let ctx = TraceContext::new();
        assert!(ctx.parent_span_id.is_none());
        assert!(ctx.baggage.is_empty());
    }

    #[test]
    fn test_trace_context_with_correlation_id() {
        let id = Uuid::new_v4();
        let ctx = TraceContext::with_correlation_id(id);
        assert_eq!(ctx.correlation_id, id);
    }

    #[test]
    fn test_trace_context_builder() {
        let id = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let ctx = TraceContext::with_correlation_id(id)
            .with_parent(parent)
            .with_baggage("tenant", "acme");

        assert_eq!(ctx.correlation_id, id);
        assert_eq!(ctx.parent_span_id, Some(parent));
        assert_eq!(ctx.baggage.get("tenant"), Some(&"acme".to_string()));
    }

    #[test]
    fn test_extract_x_correlation_id() {
        let mut headers = HashMap::new();
        headers.insert(
            "X-Correlation-ID".to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
        );

        let id = extract_from_headers(&headers);
        assert!(id.is_some());
        assert_eq!(
            id.expect("should have ID").to_string(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_extract_x_request_id() {
        let mut headers = HashMap::new();
        headers.insert(
            "X-Request-ID".to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
        );

        let id = extract_from_headers(&headers);
        assert!(id.is_some());
    }

    #[test]
    fn test_extract_traceparent() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".to_string(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        );

        let id = extract_from_headers(&headers);
        assert!(id.is_some());
    }

    #[test]
    fn test_extract_priority() {
        let mut headers = HashMap::new();
        // X-Correlation-ID should take priority
        headers.insert(
            "X-Correlation-ID".to_string(),
            "11111111-1111-1111-1111-111111111111".to_string(),
        );
        headers.insert(
            "X-Request-ID".to_string(),
            "22222222-2222-2222-2222-222222222222".to_string(),
        );

        let id = extract_from_headers(&headers);
        assert_eq!(
            id.expect("should have ID").to_string(),
            "11111111-1111-1111-1111-111111111111"
        );
    }

    #[test]
    fn test_inject_to_headers() {
        let mut headers = HashMap::new();
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid UUID");

        inject_to_headers(&mut headers, id);

        assert!(headers.contains_key("X-Correlation-ID"));
        assert!(headers.contains_key("X-Request-ID"));
        assert!(headers.contains_key("traceparent"));
    }

    #[test]
    fn test_inject_traceparent_format() {
        let mut headers = HashMap::new();
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid UUID");

        inject_to_headers(&mut headers, id);

        let traceparent = headers.get("traceparent").expect("should have traceparent");
        assert!(traceparent.starts_with("00-"));
        assert!(traceparent.ends_with("-01"));

        // Should have 4 parts
        let parts: Vec<&str> = traceparent.split('-').collect();
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn test_extract_baggage() {
        let mut headers = HashMap::new();
        headers.insert(
            "baggage".to_string(),
            "tenant=acme,region=us-east".to_string(),
        );

        let ctx = extract_correlation_id(&headers);
        assert_eq!(ctx.baggage.get("tenant"), Some(&"acme".to_string()));
        assert_eq!(ctx.baggage.get("region"), Some(&"us-east".to_string()));
    }

    #[test]
    fn test_inject_baggage() {
        let mut headers = HashMap::new();
        let ctx = TraceContext::new()
            .with_baggage("tenant", "acme")
            .with_baggage("user", "123");

        inject_correlation_id(&mut headers, &ctx);

        let baggage = headers.get("baggage").expect("should have baggage");
        assert!(baggage.contains("tenant=acme"));
        assert!(baggage.contains("user=123"));
    }

    #[test]
    fn test_parse_traceparent() {
        let result = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        assert!(result.is_some());

        // Invalid format
        assert!(parse_traceparent("invalid").is_none());
        assert!(parse_traceparent("00-short-00f067aa0ba902b7-01").is_none());
    }

    #[test]
    fn test_case_insensitive_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "x-correlation-id".to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
        );

        let id = extract_from_headers(&headers);
        assert!(id.is_some());
    }
}
