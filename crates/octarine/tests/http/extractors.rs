//! Integration tests for HTTP extractors
//!
//! Tests that extractors correctly retrieve context and handle missing values.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::HeaderName},
    routing::get,
};
use octarine::http::{
    Authenticated, ContextLayer, CorrelationId, OptionalCorrelationId, RequestIdLayer,
    RequiredTenant, SourceIp, Tenant, UserId,
};
use tower::ServiceExt;

static X_TENANT_ID: HeaderName = HeaderName::from_static("x-tenant-id");
static X_USER_ID: HeaderName = HeaderName::from_static("x-user-id");

/// Helper to make a request and get the response
async fn call_app(app: Router, request: Request<Body>) -> axum::response::Response {
    app.oneshot(request).await.expect("request should succeed")
}

// ============================================================================
// CorrelationId Extractor Tests
// ============================================================================

#[tokio::test]
async fn test_correlation_id_fails_without_middleware() {
    // Without RequestIdLayer, CorrelationId should return 500
    let app = Router::new().route(
        "/",
        get(|CorrelationId(id): CorrelationId| async move { id.to_string() }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    // Should be 500 because middleware is not configured
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_correlation_id_succeeds_with_middleware() {
    let app = Router::new()
        .route(
            "/",
            get(|CorrelationId(id): CorrelationId| async move { id.to_string() }),
        )
        .layer(RequestIdLayer::new());

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // Should be valid UUID
    uuid::Uuid::parse_str(&body_str).expect("valid UUID");
}

#[tokio::test]
async fn test_optional_correlation_id_never_fails() {
    // Without RequestIdLayer, OptionalCorrelationId should still succeed
    let app = Router::new().route(
        "/",
        get(
            |OptionalCorrelationId(id): OptionalCorrelationId| async move {
                match id {
                    Some(uuid) => uuid.to_string(),
                    None => "none".to_string(),
                }
            },
        ),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "none");
}

#[tokio::test]
async fn test_optional_correlation_id_returns_some_with_middleware() {
    let app = Router::new()
        .route(
            "/",
            get(
                |OptionalCorrelationId(id): OptionalCorrelationId| async move {
                    match id {
                        Some(uuid) => uuid.to_string(),
                        None => "none".to_string(),
                    }
                },
            ),
        )
        .layer(RequestIdLayer::new());

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // Should be valid UUID (not "none")
    uuid::Uuid::parse_str(&body_str).expect("valid UUID");
}

// ============================================================================
// RequiredTenant Extractor Tests
// ============================================================================

#[tokio::test]
async fn test_required_tenant_fails_without_header() {
    let app = Router::new()
        .route(
            "/",
            get(|RequiredTenant(tenant): RequiredTenant| async move { tenant }),
        )
        .layer(ContextLayer::new());

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    // Should be 400 Bad Request
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_required_tenant_succeeds_with_header() {
    let app = Router::new()
        .route(
            "/",
            get(|RequiredTenant(tenant): RequiredTenant| async move { tenant }),
        )
        .layer(ContextLayer::new());

    let request = Request::builder()
        .uri("/")
        .header(&X_TENANT_ID, "acme-corp")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "acme-corp");
}

// ============================================================================
// Authenticated Extractor Tests
// ============================================================================

#[tokio::test]
async fn test_authenticated_fails_without_user() {
    let app = Router::new()
        .route(
            "/",
            get(|Authenticated(user): Authenticated| async move { user }),
        )
        .layer(ContextLayer::new());

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    // Should be 401 Unauthorized
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_authenticated_succeeds_with_user() {
    let app = Router::new()
        .route(
            "/",
            get(|Authenticated(user): Authenticated| async move { user }),
        )
        .layer(ContextLayer::new());

    let request = Request::builder()
        .uri("/")
        .header(&X_USER_ID, "user-123")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "user-123");
}

// ============================================================================
// Optional Extractors Never Fail Tests
// ============================================================================

#[tokio::test]
async fn test_tenant_extractor_never_fails() {
    // Even without ContextLayer, Tenant should succeed (just return None)
    let app = Router::new().route(
        "/",
        get(|Tenant(tenant): Tenant| async move { tenant.unwrap_or_else(|| "none".to_string()) }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_user_id_extractor_never_fails() {
    // Even without ContextLayer, UserId should succeed (just return None)
    let app = Router::new().route(
        "/",
        get(|UserId(user): UserId| async move { user.unwrap_or_else(|| "none".to_string()) }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_source_ip_extractor_never_fails() {
    // Even without ContextLayer, SourceIp should succeed (just return None)
    let app = Router::new().route(
        "/",
        get(|SourceIp(ip): SourceIp| async move { ip.unwrap_or_else(|| "none".to_string()) }),
    );

    let response = call_app(app, Request::get("/").body(Body::empty()).unwrap()).await;

    assert_eq!(response.status(), StatusCode::OK);
}

// ============================================================================
// Combined Middleware Tests
// ============================================================================

#[tokio::test]
async fn test_all_extractors_with_full_middleware_stack() {
    let app = Router::new()
        .route(
            "/",
            get(
                |CorrelationId(id): CorrelationId,
                 RequiredTenant(tenant): RequiredTenant,
                 Authenticated(user): Authenticated| async move {
                    format!("id={},tenant={},user={}", id, tenant, user)
                },
            ),
        )
        .layer(RequestIdLayer::new())
        .layer(ContextLayer::new());

    let request = Request::builder()
        .uri("/")
        .header(&X_TENANT_ID, "acme")
        .header(&X_USER_ID, "alice")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // Should have all three values
    assert!(body_str.starts_with("id="));
    assert!(body_str.contains("tenant=acme"));
    assert!(body_str.contains("user=alice"));
}
