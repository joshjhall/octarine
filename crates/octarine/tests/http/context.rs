//! Integration tests for ContextLayer
//!
//! Tests context extraction from HTTP headers.

#![allow(clippy::panic, clippy::expect_used)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::HeaderName},
    routing::get,
};
use octarine::http::{ContextLayer, SourceIp, Tenant, UserId};
use tower::ServiceExt;

static X_TENANT_ID: HeaderName = HeaderName::from_static("x-tenant-id");
static X_USER_ID: HeaderName = HeaderName::from_static("x-user-id");
static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
static X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// Helper to make a request and get the response
async fn call_app(app: Router, request: Request<Body>) -> axum::response::Response {
    app.oneshot(request).await.expect("request should succeed")
}

// ============================================================================
// Tenant ID Extraction Tests
// ============================================================================

#[tokio::test]
async fn test_extracts_tenant_id() {
    let app =
        Router::new()
            .route(
                "/",
                get(|Tenant(tenant): Tenant| async move {
                    tenant.unwrap_or_else(|| "none".to_string())
                }),
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

#[tokio::test]
async fn test_tenant_none_when_header_missing() {
    let app =
        Router::new()
            .route(
                "/",
                get(|Tenant(tenant): Tenant| async move {
                    tenant.unwrap_or_else(|| "none".to_string())
                }),
            )
            .layer(ContextLayer::new());

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "none");
}

#[tokio::test]
async fn test_custom_tenant_header() {
    static X_ORG_ID: HeaderName = HeaderName::from_static("x-org-id");

    let app =
        Router::new()
            .route(
                "/",
                get(|Tenant(tenant): Tenant| async move {
                    tenant.unwrap_or_else(|| "none".to_string())
                }),
            )
            .layer(ContextLayer::new().with_tenant_header(X_ORG_ID.clone()));

    // Standard header should NOT be extracted
    let request = Request::builder()
        .uri("/")
        .header(&X_TENANT_ID, "wrong-tenant")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app.clone(), request).await;
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    assert_eq!(
        String::from_utf8(body.to_vec()).expect("valid utf8"),
        "none"
    );

    // Custom header SHOULD be extracted
    let request = Request::builder()
        .uri("/")
        .header(&X_ORG_ID, "correct-tenant")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    assert_eq!(
        String::from_utf8(body.to_vec()).expect("valid utf8"),
        "correct-tenant"
    );
}

// ============================================================================
// User ID Extraction Tests
// ============================================================================

#[tokio::test]
async fn test_extracts_user_id() {
    let app = Router::new()
        .route(
            "/",
            get(|UserId(user): UserId| async move { user.unwrap_or_else(|| "none".to_string()) }),
        )
        .layer(ContextLayer::new());

    let request = Request::builder()
        .uri("/")
        .header(&X_USER_ID, "user-123")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "user-123");
}

// ============================================================================
// Source IP Extraction Tests
// ============================================================================

#[tokio::test]
async fn test_source_ip_from_x_forwarded_for_when_trusted() {
    let app = Router::new()
        .route(
            "/",
            get(|SourceIp(ip): SourceIp| async move { ip.unwrap_or_else(|| "none".to_string()) }),
        )
        .layer(ContextLayer::new().trust_forwarded_for(true));

    let request = Request::builder()
        .uri("/")
        .header(
            &X_FORWARDED_FOR,
            "203.0.113.50, 70.41.3.18, 150.172.238.178",
        )
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // Should use first IP (client IP)
    assert_eq!(body_str, "203.0.113.50");
}

#[tokio::test]
async fn test_source_ip_ignores_x_forwarded_for_when_not_trusted() {
    let app = Router::new()
        .route(
            "/",
            get(|SourceIp(ip): SourceIp| async move { ip.unwrap_or_else(|| "none".to_string()) }),
        )
        .layer(ContextLayer::new().trust_forwarded_for(false));

    let request = Request::builder()
        .uri("/")
        .header(&X_FORWARDED_FOR, "spoofed-ip")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // Should NOT use the header value (no ConnectInfo in this test, so none)
    assert_eq!(body_str, "none");
}

#[tokio::test]
async fn test_source_ip_from_x_real_ip_when_trusted() {
    let app = Router::new()
        .route(
            "/",
            get(|SourceIp(ip): SourceIp| async move { ip.unwrap_or_else(|| "none".to_string()) }),
        )
        .layer(ContextLayer::new().trust_forwarded_for(true));

    // X-Real-IP without X-Forwarded-For
    let request = Request::builder()
        .uri("/")
        .header(&X_REAL_IP, "192.168.1.100")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "192.168.1.100");
}

#[tokio::test]
async fn test_x_forwarded_for_takes_precedence_over_x_real_ip() {
    let app = Router::new()
        .route(
            "/",
            get(|SourceIp(ip): SourceIp| async move { ip.unwrap_or_else(|| "none".to_string()) }),
        )
        .layer(ContextLayer::new().trust_forwarded_for(true));

    let request = Request::builder()
        .uri("/")
        .header(&X_FORWARDED_FOR, "10.0.0.1")
        .header(&X_REAL_IP, "10.0.0.2")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // X-Forwarded-For should take precedence
    assert_eq!(body_str, "10.0.0.1");
}

// ============================================================================
// Combined Context Tests
// ============================================================================

#[tokio::test]
async fn test_extracts_all_context() {
    let app = Router::new()
        .route(
            "/",
            get(
                |Tenant(tenant): Tenant, UserId(user): UserId, SourceIp(ip): SourceIp| async move {
                    format!(
                        "tenant={},user={},ip={}",
                        tenant.unwrap_or_default(),
                        user.unwrap_or_default(),
                        ip.unwrap_or_default()
                    )
                },
            ),
        )
        .layer(ContextLayer::new().trust_forwarded_for(true));

    let request = Request::builder()
        .uri("/")
        .header(&X_TENANT_ID, "acme")
        .header(&X_USER_ID, "alice")
        .header(&X_FORWARDED_FOR, "1.2.3.4")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "tenant=acme,user=alice,ip=1.2.3.4");
}

// ============================================================================
// Header Case Insensitivity Tests
// ============================================================================

#[tokio::test]
async fn test_tenant_header_case_insensitive() {
    let app =
        Router::new()
            .route(
                "/",
                get(|Tenant(tenant): Tenant| async move {
                    tenant.unwrap_or_else(|| "none".to_string())
                }),
            )
            .layer(ContextLayer::new());

    // HTTP headers are case-insensitive per RFC 7230
    // Test with different casings
    for header_name in ["x-tenant-id", "X-Tenant-ID", "X-TENANT-ID", "x-Tenant-Id"] {
        let request = Request::builder()
            .uri("/")
            .header(header_name, "case-test")
            .body(Body::empty())
            .expect("valid request");

        let response = call_app(app.clone(), request).await;

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("read body");
        let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

        assert_eq!(
            body_str, "case-test",
            "Header '{}' should be recognized",
            header_name
        );
    }
}

#[tokio::test]
async fn test_user_header_case_insensitive() {
    let app = Router::new()
        .route(
            "/",
            get(|UserId(user): UserId| async move { user.unwrap_or_else(|| "none".to_string()) }),
        )
        .layer(ContextLayer::new());

    // Test with uppercase variant
    let request = Request::builder()
        .uri("/")
        .header("X-USER-ID", "user-123")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "user-123");
}

// ============================================================================
// Malformed Header Handling Tests
// ============================================================================

#[tokio::test]
async fn test_handles_empty_tenant_header() {
    let app =
        Router::new()
            .route(
                "/",
                get(|Tenant(tenant): Tenant| async move {
                    tenant.unwrap_or_else(|| "none".to_string())
                }),
            )
            .layer(ContextLayer::new());

    let request = Request::builder()
        .uri("/")
        .header(&X_TENANT_ID, "")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // Empty string is still a valid value
    assert_eq!(body_str, "");
}

#[tokio::test]
async fn test_handles_whitespace_in_forwarded_for() {
    let app = Router::new()
        .route(
            "/",
            get(|SourceIp(ip): SourceIp| async move { ip.unwrap_or_else(|| "none".to_string()) }),
        )
        .layer(ContextLayer::new().trust_forwarded_for(true));

    // X-Forwarded-For with extra whitespace
    let request = Request::builder()
        .uri("/")
        .header(&X_FORWARDED_FOR, "  10.0.0.1  ,  10.0.0.2  ")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    // Should trim whitespace from first IP
    assert_eq!(body_str, "10.0.0.1");
}

#[tokio::test]
async fn test_handles_special_characters_in_tenant() {
    let app =
        Router::new()
            .route(
                "/",
                get(|Tenant(tenant): Tenant| async move {
                    tenant.unwrap_or_else(|| "none".to_string())
                }),
            )
            .layer(ContextLayer::new());

    // Tenant ID with special characters (should be passed through as-is)
    let request = Request::builder()
        .uri("/")
        .header(&X_TENANT_ID, "org-123_test.corp")
        .body(Body::empty())
        .expect("valid request");

    let response = call_app(app, request).await;

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    let body_str = String::from_utf8(body.to_vec()).expect("valid utf8");

    assert_eq!(body_str, "org-123_test.corp");
}

// ============================================================================
// Context Isolation Tests
// ============================================================================

#[tokio::test]
async fn test_context_does_not_leak_between_requests() {
    // This test verifies that context from one request doesn't leak to another
    let app =
        Router::new()
            .route(
                "/",
                get(|Tenant(tenant): Tenant| async move {
                    tenant.unwrap_or_else(|| "none".to_string())
                }),
            )
            .layer(ContextLayer::new());

    // First request with tenant
    let request1 = Request::builder()
        .uri("/")
        .header(&X_TENANT_ID, "tenant-a")
        .body(Body::empty())
        .expect("valid request");

    let response1 = call_app(app.clone(), request1).await;
    let body1 = axum::body::to_bytes(response1.into_body(), 1024)
        .await
        .expect("read body");
    assert_eq!(
        String::from_utf8(body1.to_vec()).expect("valid utf8"),
        "tenant-a"
    );

    // Second request WITHOUT tenant header
    let request2 = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let response2 = call_app(app.clone(), request2).await;
    let body2 = axum::body::to_bytes(response2.into_body(), 1024)
        .await
        .expect("read body");

    // Should NOT see tenant-a from previous request
    assert_eq!(
        String::from_utf8(body2.to_vec()).expect("valid utf8"),
        "none",
        "Context from previous request should not leak"
    );

    // Third request with different tenant
    let request3 = Request::builder()
        .uri("/")
        .header(&X_TENANT_ID, "tenant-b")
        .body(Body::empty())
        .expect("valid request");

    let response3 = call_app(app, request3).await;
    let body3 = axum::body::to_bytes(response3.into_body(), 1024)
        .await
        .expect("read body");
    assert_eq!(
        String::from_utf8(body3.to_vec()).expect("valid utf8"),
        "tenant-b"
    );
}
