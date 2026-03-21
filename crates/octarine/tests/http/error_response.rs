//! Integration tests for ProblemResponse
//!
//! Tests HTTP status code mapping and JSON body structure.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::type_complexity
)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use octarine::Problem;
use octarine::http::{ProblemResponse, RequestIdLayer};
use serde::Deserialize;
use std::time::Duration;
use tower::ServiceExt;

/// Helper to make a request and get the response
async fn call_app(app: Router, request: Request<Body>) -> axum::response::Response {
    app.oneshot(request).await.expect("request should succeed")
}

/// Deserialized error response body
#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: ErrorInfo,
}

#[derive(Debug, Deserialize)]
struct ErrorInfo {
    code: String,
    message: String,
    request_id: Option<String>,
}

// ============================================================================
// Status Code Mapping Tests
// ============================================================================

#[tokio::test]
async fn test_validation_error_returns_400() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::Validation(
                "bad input".into(),
            )))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_not_found_returns_404() {
    let app = Router::new().route(
        "/",
        get(|| async { Err::<String, _>(ProblemResponse::from(Problem::NotFound("item".into()))) }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_auth_error_returns_401() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::Auth("invalid token".into())))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_permission_denied_returns_403() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::PermissionDenied(
                "no access".into(),
            )))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_already_exists_returns_409() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::AlreadyExists("user".into())))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_rate_limited_returns_429() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::RateLimited(
                Duration::from_secs(60),
            )))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_timeout_returns_504() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::Timeout("db query".into())))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn test_network_error_returns_502() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::Network(
                "upstream failed".into(),
            )))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn test_database_error_returns_500() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::Database(
                "connection failed".into(),
            )))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_runtime_error_returns_500() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::Runtime(
                "worker panic".into(),
            )))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ============================================================================
// JSON Body Structure Tests
// ============================================================================

#[tokio::test]
async fn test_error_body_has_correct_structure() {
    let app = Router::new().route(
        "/",
        get(|| async {
            Err::<String, _>(ProblemResponse::from(Problem::Validation(
                "email is required".into(),
            )))
        }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("read body");

    let error_body: ErrorBody = serde_json::from_slice(&body).expect("valid JSON");

    assert_eq!(error_body.error.code, "validation_error");
    assert!(error_body.error.message.contains("email is required"));
    // No request ID without RequestIdLayer
    assert!(error_body.error.request_id.is_none());
}

#[tokio::test]
async fn test_error_body_includes_request_id_when_available() {
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                Err::<String, _>(ProblemResponse::from(Problem::NotFound("pattern".into())))
            }),
        )
        .layer(RequestIdLayer::new());

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("read body");

    let error_body: ErrorBody = serde_json::from_slice(&body).expect("valid JSON");

    assert_eq!(error_body.error.code, "not_found");
    // Should have request ID from middleware
    assert!(error_body.error.request_id.is_some());

    // Should be valid UUID
    let request_id = error_body.error.request_id.unwrap();
    uuid::Uuid::parse_str(&request_id).expect("valid UUID");
}

// ============================================================================
// Error Code Tests
// ============================================================================

/// Helper to create a problem and expected code pair
fn problem_code_cases() -> Vec<(fn() -> Problem, &'static str, &'static str)> {
    vec![
        (
            || Problem::Validation("test".into()),
            "validation_error",
            "Validation",
        ),
        (|| Problem::Config("test".into()), "config_error", "Config"),
        (
            || Problem::Conversion("test".into()),
            "conversion_error",
            "Conversion",
        ),
        (
            || Problem::Sanitization("test".into()),
            "sanitization_error",
            "Sanitization",
        ),
        (|| Problem::Parse("test".into()), "parse_error", "Parse"),
        (
            || Problem::Network("test".into()),
            "network_error",
            "Network",
        ),
        (
            || Problem::Auth("test".into()),
            "authentication_error",
            "Auth",
        ),
        (
            || Problem::PermissionDenied("test".into()),
            "permission_denied",
            "PermissionDenied",
        ),
        (|| Problem::NotFound("test".into()), "not_found", "NotFound"),
        (
            || Problem::AlreadyExists("test".into()),
            "already_exists",
            "AlreadyExists",
        ),
        (
            || Problem::RateLimited(Duration::from_secs(1)),
            "rate_limited",
            "RateLimited",
        ),
        (|| Problem::Timeout("test".into()), "timeout", "Timeout"),
        (
            || Problem::Runtime("test".into()),
            "runtime_error",
            "Runtime",
        ),
        (
            || Problem::Database("test".into()),
            "database_error",
            "Database",
        ),
        (
            || Problem::OperationFailed("test".into()),
            "operation_failed",
            "OperationFailed",
        ),
        (|| Problem::Other("test".into()), "internal_error", "Other"),
    ]
}

#[tokio::test]
async fn test_all_problem_variants_have_correct_codes() {
    for (make_problem, expected_code, variant_name) in problem_code_cases() {
        let app = Router::new().route(
            "/",
            get(move || async move { Err::<String, _>(ProblemResponse::from(make_problem())) }),
        );

        let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("read body");

        let error_body: ErrorBody = serde_json::from_slice(&body).expect("valid JSON");

        assert_eq!(
            error_body.error.code, expected_code,
            "Problem::{} should have code '{}'",
            variant_name, expected_code
        );
    }
}

// Note: IO error test skipped as Problem::Io(std::io::Error) cannot be easily constructed
// in tests without actual I/O operations
