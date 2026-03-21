//! Integration tests for RequestIdLayer
//!
//! Tests request ID generation, preservation, and propagation.

#![allow(clippy::panic, clippy::expect_used)]

use std::collections::HashSet;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::HeaderName},
    routing::get,
};
use octarine::http::{CorrelationId, RequestIdLayer};
use tower::ServiceExt;
use uuid::Uuid;

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Helper to make a request and get the response
async fn call_app(app: Router, request: Request<Body>) -> axum::response::Response {
    app.oneshot(request).await.expect("request should succeed")
}

// ============================================================================
// Request ID Generation Tests
// ============================================================================

#[tokio::test]
async fn test_generates_request_id_when_missing() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RequestIdLayer::new());

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // Response should have X-Request-ID header
    let request_id = response
        .headers()
        .get(&X_REQUEST_ID)
        .expect("should have request ID header");

    // Should be a valid UUID
    let id_str = request_id.to_str().expect("valid string");
    Uuid::parse_str(id_str).expect("should be valid UUID");
}

#[tokio::test]
async fn test_preserves_valid_request_id() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RequestIdLayer::new());

    let existing_id = Uuid::new_v4();
    let request = Request::builder()
        .uri("/")
        .header(&X_REQUEST_ID, existing_id.to_string())
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // Response should have the same request ID
    let request_id = response
        .headers()
        .get(&X_REQUEST_ID)
        .expect("should have request ID header");

    assert_eq!(
        request_id.to_str().expect("valid header string"),
        existing_id.to_string()
    );
}

#[tokio::test]
async fn test_generates_new_id_for_invalid_uuid() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RequestIdLayer::new());

    let request = Request::builder()
        .uri("/")
        .header(&X_REQUEST_ID, "not-a-valid-uuid")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // Response should have a NEW valid UUID (not the invalid one)
    let request_id = response
        .headers()
        .get(&X_REQUEST_ID)
        .expect("should have request ID header");

    let id_str = request_id.to_str().expect("valid string");
    assert_ne!(id_str, "not-a-valid-uuid");
    Uuid::parse_str(id_str).expect("should be valid UUID");
}

#[tokio::test]
async fn test_request_id_available_in_handler() {
    let app = Router::new()
        .route(
            "/",
            get(|CorrelationId(id): CorrelationId| async move { id.to_string() }),
        )
        .layer(RequestIdLayer::new());

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // The body should contain the request ID
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // Should be a valid UUID
    Uuid::parse_str(&body_str).expect("handler received valid UUID");
}

// ============================================================================
// Custom Header Tests
// ============================================================================

#[tokio::test]
async fn test_custom_header_name() {
    static X_CORRELATION_ID: HeaderName = HeaderName::from_static("x-correlation-id");

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RequestIdLayer::new().with_header_name(X_CORRELATION_ID.clone()));

    let existing_id = Uuid::new_v4();
    let request = Request::builder()
        .uri("/")
        .header(&X_CORRELATION_ID, existing_id.to_string())
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    // Response should have X-Correlation-ID (not X-Request-ID)
    assert!(response.headers().get(&X_REQUEST_ID).is_none());

    let correlation_id = response
        .headers()
        .get(&X_CORRELATION_ID)
        .expect("should have correlation ID header");

    assert_eq!(
        correlation_id.to_str().expect("valid header string"),
        existing_id.to_string()
    );
}

// ============================================================================
// Request Header Propagation Tests
// ============================================================================

#[tokio::test]
async fn test_adds_header_to_request_when_missing() {
    // This test verifies that downstream services would receive the request ID
    let app = Router::new()
        .route(
            "/",
            get(|request: Request<Body>| async move {
                // Check if the request has the header (set by middleware)
                if request.headers().contains_key(&X_REQUEST_ID) {
                    "has-header"
                } else {
                    "no-header"
                }
            }),
        )
        .layer(RequestIdLayer::new());

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "has-header");
}

// ============================================================================
// Header Case Insensitivity Tests
// ============================================================================

#[tokio::test]
async fn test_request_id_header_case_insensitive() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RequestIdLayer::new());

    let existing_id = Uuid::new_v4();

    // HTTP headers are case-insensitive - test with different casings
    for header_name in ["x-request-id", "X-Request-ID", "X-REQUEST-ID"] {
        let request = Request::builder()
            .uri("/")
            .header(header_name, existing_id.to_string())
            .body(Body::empty())
            .expect("valid request");

        let response = call_app(app.clone(), request).await;

        let request_id = response
            .headers()
            .get(&X_REQUEST_ID)
            .expect("should have request ID header");

        assert_eq!(
            request_id.to_str().expect("valid header string"),
            existing_id.to_string(),
            "Header '{}' should be recognized",
            header_name
        );
    }
}

// ============================================================================
// Malformed Header Handling Tests
// ============================================================================

#[tokio::test]
async fn test_empty_request_id_generates_new() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RequestIdLayer::new());

    let request = Request::builder()
        .uri("/")
        .header(&X_REQUEST_ID, "")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let request_id = response
        .headers()
        .get(&X_REQUEST_ID)
        .expect("should have request ID header");

    // Empty string is not a valid UUID, so a new one should be generated
    let id_str = request_id.to_str().expect("valid string");
    assert!(!id_str.is_empty());
    Uuid::parse_str(id_str).expect("should be valid UUID");
}

#[tokio::test]
async fn test_whitespace_request_id_generates_new() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RequestIdLayer::new());

    let request = Request::builder()
        .uri("/")
        .header(&X_REQUEST_ID, "   ")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let request_id = response
        .headers()
        .get(&X_REQUEST_ID)
        .expect("should have request ID header");

    // Whitespace is not a valid UUID
    let id_str = request_id.to_str().expect("valid string");
    Uuid::parse_str(id_str).expect("should be valid UUID");
}

#[tokio::test]
async fn test_partial_uuid_generates_new() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(RequestIdLayer::new());

    // Partial/truncated UUID
    let request = Request::builder()
        .uri("/")
        .header(&X_REQUEST_ID, "550e8400-e29b-41d4")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let request_id = response
        .headers()
        .get(&X_REQUEST_ID)
        .expect("should have request ID header");

    let id_str = request_id.to_str().expect("valid string");
    // Should be a new valid UUID, not the partial one
    assert_ne!(id_str, "550e8400-e29b-41d4");
    Uuid::parse_str(id_str).expect("should be valid UUID");
}

// ============================================================================
// Context Isolation Tests
// ============================================================================

#[tokio::test]
async fn test_correlation_id_unique_per_request() {
    let app = Router::new()
        .route(
            "/",
            get(|CorrelationId(id): CorrelationId| async move { id.to_string() }),
        )
        .layer(RequestIdLayer::new());

    // Make multiple requests without providing request ID
    let mut ids = HashSet::new();
    let request_count = 3;

    for _ in 0..request_count {
        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .expect("valid request");

        let response = call_app(app.clone(), request).await;

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("read body");
        let id_str = String::from_utf8(body.to_vec()).expect("valid utf8");

        ids.insert(id_str);
    }

    // All IDs should be unique - if any were duplicates, the set would be smaller
    assert_eq!(
        ids.len(),
        request_count,
        "All {} request IDs should be unique",
        request_count
    );
}
