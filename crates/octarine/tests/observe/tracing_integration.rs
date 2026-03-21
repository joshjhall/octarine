//! Integration tests for tracing crate integration
//!
//! Tests the ObserveLayer, span correlation, and HTTP propagation.

#![allow(clippy::panic, clippy::expect_used)]

use std::collections::HashMap;
use uuid::Uuid;

use octarine::observe::Severity;
use octarine::observe::tracing::{
    ObserveLayer, TraceContext, TracingConfig, extract_correlation_id, extract_from_headers,
    inject_correlation_id, inject_to_headers,
};

// ============================================================================
// TracingConfig Tests
// ============================================================================

#[test]
fn test_tracing_config_defaults() {
    let config = TracingConfig::default();
    assert!(config.capture_spans);
    assert!(config.propagate_correlation);
    assert_eq!(config.buffer_size, 10_000);
}

#[test]
fn test_tracing_config_builder() {
    let config = TracingConfig::new()
        .min_level(Severity::Warning)
        .capture_spans(false)
        .buffer_size(5000)
        .default_operation("myapp");

    assert!(!config.capture_spans);
    assert_eq!(config.buffer_size, 5000);
    assert_eq!(config.default_operation, "myapp");
}

#[test]
fn test_tracing_config_presets() {
    let prod = TracingConfig::production();
    assert_eq!(prod.min_level, Severity::Info);

    let dev = TracingConfig::development();
    assert_eq!(dev.min_level, Severity::Debug);

    let minimal = TracingConfig::minimal();
    assert_eq!(minimal.min_level, Severity::Warning);
    assert!(!minimal.capture_spans);
}

// ============================================================================
// ObserveLayer Tests
// ============================================================================

#[test]
fn test_observe_layer_creation() {
    let _layer = ObserveLayer::new(TracingConfig::default());
    // Layer should be created without error
}

#[test]
fn test_observe_layer_with_config() {
    let config = TracingConfig::new()
        .min_level(Severity::Info)
        .capture_spans(true);

    let _layer = ObserveLayer::new(config);
}

// ============================================================================
// HTTP Header Propagation Tests
// ============================================================================

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
fn test_extract_header_priority() {
    let mut headers = HashMap::new();
    // X-Correlation-ID should take priority over X-Request-ID
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
fn test_extract_missing_headers() {
    let headers: HashMap<String, String> = HashMap::new();
    let id = extract_from_headers(&headers);
    assert!(id.is_none());
}

#[test]
fn test_extract_invalid_uuid() {
    let mut headers = HashMap::new();
    headers.insert("X-Correlation-ID".to_string(), "not-a-uuid".to_string());

    let id = extract_from_headers(&headers);
    assert!(id.is_none());
}

#[test]
fn test_inject_to_headers() {
    let mut headers = HashMap::new();
    let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid UUID");

    inject_to_headers(&mut headers, id);

    assert!(headers.contains_key("X-Correlation-ID"));
    assert!(headers.contains_key("X-Request-ID"));
    assert!(headers.contains_key("traceparent"));

    assert_eq!(
        headers.get("X-Correlation-ID").expect("should have header"),
        "550e8400-e29b-41d4-a716-446655440000"
    );
}

#[test]
fn test_inject_traceparent_format() {
    let mut headers = HashMap::new();
    let id = Uuid::new_v4();

    inject_to_headers(&mut headers, id);

    let traceparent = headers.get("traceparent").expect("should have traceparent");
    // W3C format: {version}-{trace_id}-{parent_id}-{flags}
    assert!(traceparent.starts_with("00-"));
    assert!(traceparent.ends_with("-01"));

    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts.first().expect("version"), &"00"); // version
    assert_eq!(parts.get(1).expect("trace_id").len(), 32); // trace_id (32 hex chars)
    assert_eq!(parts.get(2).expect("parent_id").len(), 16); // parent_id (16 hex chars)
    assert_eq!(parts.get(3).expect("flags"), &"01"); // flags
}

#[test]
fn test_roundtrip_correlation_id() {
    let original_id = Uuid::new_v4();

    // Inject into headers
    let mut headers = HashMap::new();
    inject_to_headers(&mut headers, original_id);

    // Extract from headers
    let extracted_id = extract_from_headers(&headers);

    assert_eq!(extracted_id, Some(original_id));
}

// ============================================================================
// TraceContext Tests
// ============================================================================

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
        .with_baggage("tenant", "acme-corp")
        .with_baggage("region", "us-east-1");

    assert_eq!(ctx.correlation_id, id);
    assert_eq!(ctx.parent_span_id, Some(parent));
    assert_eq!(ctx.baggage.get("tenant"), Some(&"acme-corp".to_string()));
    assert_eq!(ctx.baggage.get("region"), Some(&"us-east-1".to_string()));
}

#[test]
fn test_extract_full_context() {
    let mut headers = HashMap::new();
    headers.insert(
        "X-Correlation-ID".to_string(),
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
    );
    headers.insert(
        "baggage".to_string(),
        "tenant=acme,region=us-east".to_string(),
    );

    let ctx = extract_correlation_id(&headers);

    assert_eq!(
        ctx.correlation_id.to_string(),
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(ctx.baggage.get("tenant"), Some(&"acme".to_string()));
    assert_eq!(ctx.baggage.get("region"), Some(&"us-east".to_string()));
}

#[test]
fn test_inject_full_context() {
    let mut headers = HashMap::new();
    let ctx = TraceContext::new()
        .with_baggage("tenant", "acme")
        .with_baggage("user_id", "12345");

    inject_correlation_id(&mut headers, &ctx);

    assert!(headers.contains_key("X-Correlation-ID"));
    assert!(headers.contains_key("baggage"));

    let baggage = headers.get("baggage").expect("should have baggage");
    assert!(baggage.contains("tenant=acme"));
    assert!(baggage.contains("user_id=12345"));
}

// ============================================================================
// Case Insensitive Header Tests
// ============================================================================

#[test]
fn test_case_insensitive_header_extraction() {
    let mut headers = HashMap::new();
    headers.insert(
        "x-correlation-id".to_string(),
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
    );

    let id = extract_from_headers(&headers);
    assert!(id.is_some());
}

#[test]
fn test_mixed_case_headers() {
    let mut headers = HashMap::new();
    headers.insert(
        "X-REQUEST-ID".to_string(),
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
    );

    let id = extract_from_headers(&headers);
    assert!(id.is_some());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_baggage() {
    let mut headers = HashMap::new();
    headers.insert("baggage".to_string(), "".to_string());

    let ctx = extract_correlation_id(&headers);
    assert!(ctx.baggage.is_empty());
}

#[test]
fn test_malformed_baggage() {
    let mut headers = HashMap::new();
    headers.insert("baggage".to_string(), "invalid-format".to_string());

    let ctx = extract_correlation_id(&headers);
    // Should handle gracefully - no valid key=value pairs
    assert!(ctx.baggage.is_empty());
}

#[test]
fn test_inject_empty_baggage() {
    let mut headers = HashMap::new();
    let ctx = TraceContext::new(); // No baggage

    inject_correlation_id(&mut headers, &ctx);

    // Should not add baggage header if empty
    assert!(!headers.contains_key("baggage"));
}
