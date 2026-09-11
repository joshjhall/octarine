//! Behavioral integration tests for `AuthLayer` and `RateLimitLayer`.
//!
//! The inline unit tests in `src/http/middleware/{auth,rate_limit}.rs` only
//! confirm that the config structs are built correctly — neither layer is ever
//! mounted, so nothing verifies that `AuthLayer` actually returns 401 or that
//! `RateLimitLayer` actually returns 429 (issue #413).
//!
//! These tests mount each layer on a real `axum::Router` and dispatch through
//! `tower::ServiceExt::oneshot`, the same pattern as `tests/http/request_id.rs`
//! and `tests/http/presets.rs`.
//!
//! ## Conventions
//!
//! - No wall-clock sleeps. The rate-limit budget is exhausted synchronously
//!   inside a single test; "allowed again after the window elapses" would need
//!   a real sleep and is deliberately not asserted (`octarine-test-resilience`).
//! - JWTs are minted in-test with `jsonwebtoken` (a dev-dependency): the crate
//!   validates tokens but does not re-export an encoder.

#![allow(clippy::panic, clippy::expect_used)]

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::Body,
    http::{HeaderName, Request, StatusCode, header},
    routing::get,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use octarine::http::middleware::{AuthConfig, AuthLayer, Claims, RateLimitConfig, RateLimitLayer};
use tower::ServiceExt;

const JWT_SECRET: &str = "test-secret-for-issue-413";
const OTHER_SECRET: &str = "a-completely-different-secret";

/// Seconds since the Unix epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

/// Mint an HS256 JWT signed with `secret`, valid for one hour.
fn mint_jwt(secret: &str, subject: &str) -> String {
    let now = now_secs();
    let claims = Claims {
        sub: subject.to_string(),
        exp: now.saturating_add(3600),
        iat: Some(now),
        tenant_id: None,
        roles: Vec::new(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("claims should encode")
}

/// A router with a single `/protected` handler and no middleware yet.
fn base_router() -> Router {
    Router::new()
        .route("/protected", get(|| async { "ok" }))
        .route("/health", get(|| async { "healthy" }))
}

/// Dispatch one request through `app`.
async fn call(app: Router, request: Request<Body>) -> axum::response::Response {
    app.oneshot(request).await.expect("request should dispatch")
}

/// Build a GET request for `path` with optional headers.
fn get_request(path: &str, headers: &[(HeaderName, String)]) -> Request<Body> {
    let mut builder = Request::builder().uri(path);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(Body::empty()).expect("valid request")
}

// ============================================================================
// AuthLayer — JWT
// ============================================================================

/// A request with no `Authorization` header is rejected with 401.
#[tokio::test]
async fn test_auth_layer_rejects_missing_credentials() {
    let app = base_router().layer(AuthLayer::jwt(JWT_SECRET));

    let response = call(app, get_request("/protected", &[])).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A valid JWT reaches the handler with 200 — the positive half that rules out
/// a layer that simply rejects everything.
#[tokio::test]
async fn test_auth_layer_accepts_valid_jwt() {
    let app = base_router().layer(AuthLayer::jwt(JWT_SECRET));
    let token = mint_jwt(JWT_SECRET, "user-123");

    let response = call(
        app,
        get_request(
            "/protected",
            &[(header::AUTHORIZATION, format!("Bearer {token}"))],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
}

/// A token signed with a different secret fails signature validation.
#[tokio::test]
async fn test_auth_layer_rejects_wrong_signing_key() {
    let app = base_router().layer(AuthLayer::jwt(JWT_SECRET));
    let token = mint_jwt(OTHER_SECRET, "user-123");

    let response = call(
        app,
        get_request(
            "/protected",
            &[(header::AUTHORIZATION, format!("Bearer {token}"))],
        ),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a token signed with the wrong key must not be accepted"
    );
}

/// An expired token is rejected even though the signature is valid.
#[tokio::test]
async fn test_auth_layer_rejects_expired_token() {
    let app = base_router().layer(AuthLayer::jwt(JWT_SECRET));

    let now = now_secs();
    let claims = Claims {
        sub: "user-123".to_string(),
        exp: now.saturating_sub(3600), // expired an hour ago
        iat: Some(now.saturating_sub(7200)),
        tenant_id: None,
        roles: Vec::new(),
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .expect("claims should encode");

    let response = call(
        app,
        get_request(
            "/protected",
            &[(header::AUTHORIZATION, format!("Bearer {token}"))],
        ),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "an expired token must be rejected"
    );
}

/// A structurally invalid Bearer token is rejected.
#[tokio::test]
async fn test_auth_layer_rejects_malformed_token() {
    let app = base_router().layer(AuthLayer::jwt(JWT_SECRET));

    let response = call(
        app,
        get_request(
            "/protected",
            &[(header::AUTHORIZATION, "Bearer not-a-jwt-at-all".to_string())],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Excluded paths bypass authentication; non-excluded ones still require it.
#[tokio::test]
async fn test_auth_layer_exclude_paths() {
    let config = AuthConfig::jwt(JWT_SECRET).exclude_paths(["/health"]);
    let app = base_router().layer(AuthLayer::with_config(config));

    let excluded = call(app.clone(), get_request("/health", &[])).await;
    assert_eq!(
        excluded.status(),
        StatusCode::OK,
        "an excluded path must not require credentials"
    );

    let guarded = call(app, get_request("/protected", &[])).await;
    assert_eq!(
        guarded.status(),
        StatusCode::UNAUTHORIZED,
        "a non-excluded path must still require credentials"
    );
}

/// `optional()` lets credential-free requests through, but still rejects
/// credentials that are present and invalid.
#[tokio::test]
async fn test_auth_layer_optional_allows_anonymous_but_rejects_invalid() {
    let app = base_router().layer(AuthLayer::with_config(
        AuthConfig::jwt(JWT_SECRET).optional(),
    ));

    let anonymous = call(app.clone(), get_request("/protected", &[])).await;
    assert_eq!(
        anonymous.status(),
        StatusCode::OK,
        "optional auth must allow a request with no credentials"
    );

    let bad_token = mint_jwt(OTHER_SECRET, "user-123");
    let invalid = call(
        app,
        get_request(
            "/protected",
            &[(header::AUTHORIZATION, format!("Bearer {bad_token}"))],
        ),
    )
    .await;
    assert_eq!(
        invalid.status(),
        StatusCode::UNAUTHORIZED,
        "optional auth must still reject credentials that are present and bad"
    );
}

// ============================================================================
// AuthLayer — API key
// ============================================================================

static X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// The configured validator decides: an accepted key passes, a rejected key
/// 401s, and a missing key 401s.
#[tokio::test]
async fn test_auth_layer_api_key_validator_decides() {
    let config = AuthConfig::api_key(|key: &str| {
        if key == "good-key" {
            Some(("svc-account".to_string(), None))
        } else {
            None
        }
    });
    let app = base_router().layer(AuthLayer::with_config(config));

    let accepted = call(
        app.clone(),
        get_request("/protected", &[(X_API_KEY.clone(), "good-key".to_string())]),
    )
    .await;
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "the validator accepted this key, so the request must reach the handler"
    );

    let rejected = call(
        app.clone(),
        get_request("/protected", &[(X_API_KEY.clone(), "bad-key".to_string())]),
    )
    .await;
    assert_eq!(
        rejected.status(),
        StatusCode::UNAUTHORIZED,
        "the validator rejected this key"
    );

    let missing = call(app, get_request("/protected", &[])).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
}

/// `both()` accepts either credential type on the same route.
#[tokio::test]
async fn test_auth_layer_both_accepts_jwt_or_api_key() {
    let config = AuthConfig::both(JWT_SECRET, |key: &str| {
        (key == "good-key").then(|| ("svc-account".to_string(), None))
    });
    let app = base_router().layer(AuthLayer::with_config(config));

    let token = mint_jwt(JWT_SECRET, "user-123");
    let via_jwt = call(
        app.clone(),
        get_request(
            "/protected",
            &[(header::AUTHORIZATION, format!("Bearer {token}"))],
        ),
    )
    .await;
    assert_eq!(via_jwt.status(), StatusCode::OK, "JWT path must work");

    let via_key = call(
        app.clone(),
        get_request("/protected", &[(X_API_KEY.clone(), "good-key".to_string())]),
    )
    .await;
    assert_eq!(via_key.status(), StatusCode::OK, "API key path must work");

    let neither = call(app, get_request("/protected", &[])).await;
    assert_eq!(
        neither.status(),
        StatusCode::UNAUTHORIZED,
        "with neither credential the request must still be rejected"
    );
}

// ============================================================================
// RateLimitLayer
// ============================================================================

/// A global limiter allows the burst and then returns 429 with `Retry-After`
/// and the documented JSON error body.
#[tokio::test]
async fn test_rate_limit_layer_returns_429_after_burst() {
    let burst = 3u32;
    let config = RateLimitConfig::per_second(1).with_burst(burst).global();
    let app = base_router().layer(RateLimitLayer::with_config(config));

    // The burst budget is spent synchronously — no sleeps, so the replenish
    // rate never gets a chance to interfere.
    for i in 0..burst {
        let response = call(app.clone(), get_request("/protected", &[])).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "request {i} is inside the burst of {burst} and must be allowed"
        );
    }

    let limited = call(app, get_request("/protected", &[])).await;
    assert_eq!(
        limited.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the request past the burst must be rate limited"
    );
    assert!(
        limited.headers().contains_key(header::RETRY_AFTER),
        "a 429 must carry Retry-After, got headers {:?}",
        limited.headers()
    );

    let body = axum::body::to_bytes(limited.into_body(), 64 * 1024)
        .await
        .expect("body should read");
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("rate_limited"),
        "the 429 body must carry the documented error code, got {body:?}"
    );
}

/// Excluded paths are never limited, even well past the burst — while a
/// non-excluded path on the same router still is.
#[tokio::test]
async fn test_rate_limit_layer_exclude_paths() {
    let config = RateLimitConfig::per_second(1)
        .with_burst(1)
        .global()
        .exclude_paths(["/health"]);
    let app = base_router().layer(RateLimitLayer::with_config(config));

    for i in 0..5 {
        let response = call(app.clone(), get_request("/health", &[])).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "excluded request {i} must never be limited"
        );
    }

    // The budget was untouched by the excluded requests, so the first guarded
    // request passes and the second is limited.
    let first = call(app.clone(), get_request("/protected", &[])).await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = call(app, get_request("/protected", &[])).await;
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a non-excluded path must still be limited"
    );
}

/// `KeyStrategy::PerHeader` gives each header value its own budget — spending
/// one tenant's allowance must not limit another's. Without this assertion the
/// suite could not tell keyed limiting from a single global bucket.
#[tokio::test]
async fn test_rate_limit_layer_per_header_keys_are_independent() {
    static X_TENANT: HeaderName = HeaderName::from_static("x-tenant");

    let burst = 2u32;
    let config = RateLimitConfig::per_second(1)
        .with_burst(burst)
        .per_header(X_TENANT.clone());
    let app = base_router().layer(RateLimitLayer::with_config(config));

    // Exhaust tenant-a's budget.
    for i in 0..burst {
        let response = call(
            app.clone(),
            get_request("/protected", &[(X_TENANT.clone(), "tenant-a".to_string())]),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "tenant-a request {i} is inside its burst"
        );
    }

    let a_limited = call(
        app.clone(),
        get_request("/protected", &[(X_TENANT.clone(), "tenant-a".to_string())]),
    )
    .await;
    assert_eq!(
        a_limited.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "tenant-a spent its budget"
    );

    // tenant-b has its own bucket and is unaffected.
    let b_first = call(
        app,
        get_request("/protected", &[(X_TENANT.clone(), "tenant-b".to_string())]),
    )
    .await;
    assert_eq!(
        b_first.status(),
        StatusCode::OK,
        "tenant-b must have an independent budget from tenant-a"
    );
}
