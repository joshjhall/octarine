//! Integration tests for `CorrelationLayer`
//!
//! Covers the acceptance criteria from issue #531:
//! - inbound `x-correlation-id` reaches the handler context (and thus events)
//! - invalid `x-correlation-id` is rejected; a fresh id is generated
//! - outbound `traceparent` chains with inbound when present; fresh otherwise
//! - response carries `x-correlation-id`
//! - error responses include the correlation id in the error envelope body
//! - compatible with the other middleware layers (ordering)

#![allow(clippy::panic, clippy::expect_used)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::HeaderName},
    routing::get,
};
use octarine::Problem;
use octarine::http::{
    ContextLayer, CorrelationId, CorrelationLayer, ObserveLayer, ProblemResponse,
};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

static X_CORRELATION_ID: HeaderName = HeaderName::from_static("x-correlation-id");
static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
static TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");

/// Helper to make a request and get the response.
async fn call_app(app: Router, request: Request<Body>) -> axum::response::Response {
    app.oneshot(request).await.expect("request should succeed")
}

/// Build the W3C traceparent string the way the propagation helpers do, so a
/// test can assert chaining (the trace-id is derived from the correlation id).
fn expected_trace_id(id: Uuid) -> String {
    format!("{:032x}", id.as_u128())
}

// ============================================================================
// AC1: inbound correlation id reaches the handler context
// ============================================================================

#[tokio::test]
async fn test_inbound_correlation_id_reaches_handler() {
    let app = Router::new()
        .route(
            "/",
            get(|CorrelationId(id): CorrelationId| async move { id.to_string() }),
        )
        .layer(CorrelationLayer::new());

    let inbound = Uuid::new_v4();
    let request = Request::builder()
        .uri("/")
        .header(&X_CORRELATION_ID, inbound.to_string())
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // The handler observed the SAME id as the inbound header — proving the
    // task-local scope is active for everything emitted during the request.
    assert_eq!(body_str, inbound.to_string());
}

#[tokio::test]
async fn test_inbound_request_id_header_is_accepted() {
    let app = Router::new()
        .route(
            "/",
            get(|CorrelationId(id): CorrelationId| async move { id.to_string() }),
        )
        .layer(CorrelationLayer::new());

    let inbound = Uuid::new_v4();
    let request = Request::builder()
        .uri("/")
        .header(&X_REQUEST_ID, inbound.to_string())
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, inbound.to_string());
}

// ============================================================================
// AC2: invalid correlation id is rejected; fresh id generated
// ============================================================================

#[tokio::test]
async fn test_invalid_correlation_id_is_rejected() {
    let app = Router::new()
        .route(
            "/",
            get(|CorrelationId(id): CorrelationId| async move { id.to_string() }),
        )
        .layer(CorrelationLayer::new());

    let request = Request::builder()
        .uri("/")
        .header(&X_CORRELATION_ID, "not-a-uuid; rm -rf /")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Response must carry a fresh, valid UUID — never the rejected raw value.
    let echoed = response
        .headers()
        .get(&X_CORRELATION_ID)
        .and_then(|v| v.to_str().ok())
        .expect("x-correlation-id echoed")
        .to_string();
    assert_ne!(echoed, "not-a-uuid; rm -rf /");
    Uuid::parse_str(&echoed).expect("fresh id is a valid UUID");

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");
    Uuid::parse_str(&body_str).expect("handler saw a valid UUID");
}

// ============================================================================
// AC3: traceparent chaining
// ============================================================================

#[tokio::test]
async fn test_outbound_traceparent_chains_with_inbound() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(CorrelationLayer::new());

    // W3C traceparent whose trace-id maps to a known UUID.
    let inbound = Uuid::parse_str("4bf92f35-77b3-4da6-a3ce-929d0e0e4736").expect("valid uuid");
    let traceparent_in = format!("00-{}-00f067aa0ba902b7-01", expected_trace_id(inbound));

    let request = Request::builder()
        .uri("/")
        .header(&TRACEPARENT, &traceparent_in)
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    // Outbound traceparent must carry the SAME trace-id (chained).
    let traceparent_out = response
        .headers()
        .get(&TRACEPARENT)
        .and_then(|v| v.to_str().ok())
        .expect("traceparent echoed");
    assert!(
        traceparent_out.contains(&expected_trace_id(inbound)),
        "outbound traceparent {traceparent_out} should chain inbound trace-id"
    );

    // And the echoed correlation id equals the inbound trace's UUID.
    let echoed = response
        .headers()
        .get(&X_CORRELATION_ID)
        .and_then(|v| v.to_str().ok())
        .expect("x-correlation-id echoed");
    assert_eq!(echoed, inbound.to_string());
}

#[tokio::test]
async fn test_fresh_traceparent_when_absent() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(CorrelationLayer::new());

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let traceparent_out = response
        .headers()
        .get(&TRACEPARENT)
        .and_then(|v| v.to_str().ok())
        .expect("traceparent generated");
    assert!(traceparent_out.starts_with("00-"));
    assert!(traceparent_out.ends_with("-01"));

    // Echoed correlation id is a fresh valid UUID.
    let echoed = response
        .headers()
        .get(&X_CORRELATION_ID)
        .and_then(|v| v.to_str().ok())
        .expect("x-correlation-id echoed");
    Uuid::parse_str(echoed).expect("fresh id is a valid UUID");
}

// ============================================================================
// AC4: response carries x-correlation-id
// ============================================================================

#[tokio::test]
async fn test_response_echoes_correlation_id() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(CorrelationLayer::new());

    let inbound = Uuid::new_v4();
    let request = Request::builder()
        .uri("/")
        .header(&X_CORRELATION_ID, inbound.to_string())
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let echoed = response
        .headers()
        .get(&X_CORRELATION_ID)
        .and_then(|v| v.to_str().ok())
        .expect("x-correlation-id echoed");
    assert_eq!(echoed, inbound.to_string());
}

// ============================================================================
// AC5: error responses include the correlation id in the envelope body
// ============================================================================

#[tokio::test]
async fn test_error_envelope_includes_correlation_id() {
    async fn failing() -> Result<&'static str, ProblemResponse> {
        Err(Problem::Validation("bad input".into()).into())
    }

    let app = Router::new()
        .route("/", get(failing))
        .layer(CorrelationLayer::new());

    let inbound = Uuid::new_v4();
    let request = Request::builder()
        .uri("/")
        .header(&X_CORRELATION_ID, inbound.to_string())
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("valid json");

    // The error envelope's request_id field carries the active correlation id.
    let request_id = json
        .get("error")
        .and_then(|e| e.get("request_id"))
        .and_then(|r| r.as_str())
        .expect("error.request_id present");
    assert_eq!(request_id, inbound.to_string());
}

// ============================================================================
// AC6: compatible with the other middleware layers (ordering)
// ============================================================================

#[tokio::test]
async fn test_compatible_with_observe_and_context_layers() {
    let app = Router::new()
        .route(
            "/",
            get(|CorrelationId(id): CorrelationId| async move { id.to_string() }),
        )
        // Inner-to-outer: ContextLayer, then ObserveLayer, then CorrelationLayer
        // outermost so the id is set before observe logs the request.
        .layer(ContextLayer::new())
        .layer(ObserveLayer::new())
        .layer(CorrelationLayer::new());

    let inbound = Uuid::new_v4();
    let request = Request::builder()
        .uri("/")
        .header(&X_CORRELATION_ID, inbound.to_string())
        .header("x-tenant-id", "acme")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Correlation id survives the full stack and is echoed.
    let echoed = response
        .headers()
        .get(&X_CORRELATION_ID)
        .and_then(|v| v.to_str().ok())
        .expect("x-correlation-id echoed");
    assert_eq!(echoed, inbound.to_string());

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");
    assert_eq!(body_str, inbound.to_string());
}

#[tokio::test]
async fn test_propagate_to_request_disabled_does_not_set_request_header() {
    let app = Router::new()
        .route(
            "/",
            get(|request: Request<Body>| async move {
                if request.headers().contains_key("x-correlation-id") {
                    "has-header"
                } else {
                    "no-header"
                }
            }),
        )
        .layer(CorrelationLayer::new().propagate_to_request(false));

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");
    assert_eq!(body_str, "no-header");
}
