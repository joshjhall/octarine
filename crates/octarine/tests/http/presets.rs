//! Behavioral integration tests for HTTP preset middleware.
//!
//! These tests exercise each preset by routing a request through it and
//! asserting on the resulting response. Unit tests in
//! `src/http/presets/*.rs` only confirm constructors don't panic — these
//! tests confirm the layers actually behave as documented.
//!
//! ## Conventions
//!
//! - `tokio::time::pause()` + `advance()` for timeout determinism
//!   (no wall-clock sleeps; see `octarine-test-resilience` skill).
//! - All requests are dispatched via `Router::oneshot()` from
//!   `tower::ServiceExt` — same pattern as `tests/http/request_id.rs`.

#![allow(clippy::panic, clippy::expect_used)]

use std::io::Write;
use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Method, Request, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use http_body_util::BodyExt;
use octarine::http::presets::{compression, cors, limits, timeout};
use tower::ServiceExt;

// ============================================================================
// CORS — Access-Control-* response headers
// ============================================================================

/// `development()` allows any origin and sets credentials to false (required
/// when wildcards are used).
#[tokio::test]
async fn test_cors_development_allows_any_origin() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(cors::development());

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header(header::ORIGIN, "https://random.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    let allow_origin = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("should set Access-Control-Allow-Origin");

    // development() uses AllowOrigin::any() which sets the wildcard
    assert_eq!(allow_origin, HeaderValue::from_static("*"));

    // development() must not enable credentials with a wildcard origin
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "development must not set Allow-Credentials with wildcard origin",
    );
}

/// `production(&["https://allowed"])` echoes back only the configured origin
/// and enables credentials.
#[tokio::test]
async fn test_cors_production_allows_configured_origin() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(cors::production(&["https://allowed.example.com"]));

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header(header::ORIGIN, "https://allowed.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    let allow_origin = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("should echo allowed origin");
    assert_eq!(
        allow_origin,
        HeaderValue::from_static("https://allowed.example.com"),
    );

    // production() must enable credentials
    let allow_credentials = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        .expect("should enable credentials");
    assert_eq!(allow_credentials, HeaderValue::from_static("true"));
}

/// `production(&["https://allowed"])` does NOT echo back disallowed origins.
#[tokio::test]
async fn test_cors_production_rejects_disallowed_origin() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(cors::production(&["https://allowed.example.com"]));

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header(header::ORIGIN, "https://attacker.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    // tower-http omits the Allow-Origin header entirely for non-matching origins
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "must not echo disallowed origin",
    );
}

/// `read_only(&[])` allows any origin but only GET/OPTIONS methods.
#[tokio::test]
async fn test_cors_read_only_advertises_get_only() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(cors::read_only(&[]));

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header(header::ORIGIN, "https://anyone.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    let allow_methods = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_METHODS)
        .expect("should advertise allowed methods")
        .to_str()
        .expect("ASCII methods");

    assert!(allow_methods.contains("GET"), "must allow GET");
    assert!(allow_methods.contains("OPTIONS"), "must allow OPTIONS");
    assert!(
        !allow_methods.contains("POST"),
        "read_only must not advertise POST: got {allow_methods}",
    );
    assert!(
        !allow_methods.contains("DELETE"),
        "read_only must not advertise DELETE: got {allow_methods}",
    );
}

/// `read_only` advertises a 24-hour max-age (vs 1-hour for read/write
/// presets) so browsers cache the preflight longer.
#[tokio::test]
async fn test_cors_read_only_advertises_long_max_age() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(cors::read_only(&[]));

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header(header::ORIGIN, "https://anyone.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    let max_age = response
        .headers()
        .get(header::ACCESS_CONTROL_MAX_AGE)
        .expect("should set Max-Age")
        .to_str()
        .expect("ASCII");

    assert_eq!(max_age, "86400", "read_only must use 24h max-age");
}

/// `development` and `production` advertise a 1-hour max-age.
#[tokio::test]
async fn test_cors_default_advertises_one_hour_max_age() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(cors::development());

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header(header::ORIGIN, "https://anyone.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    let max_age = response
        .headers()
        .get(header::ACCESS_CONTROL_MAX_AGE)
        .expect("should set Max-Age")
        .to_str()
        .expect("ASCII");

    assert_eq!(max_age, "3600", "development must use 1h max-age");
}

// ============================================================================
// Body limits — 413 PAYLOAD_TOO_LARGE
// ============================================================================

async fn echo_body(body: Body) -> impl IntoResponse {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    bytes.len().to_string()
}

/// `default_body()` (2 MB) rejects an oversized payload with 413.
#[tokio::test]
async fn test_limits_default_body_rejects_oversized() {
    let app = Router::new()
        .route("/", post(echo_body))
        .layer(limits::default_body());

    // 2 MB + 1 byte
    let payload = vec![0_u8; (2 * 1024 * 1024) + 1];
    let len = payload.len();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::CONTENT_LENGTH, len.to_string())
        .body(Body::from(payload))
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// `default_body()` (2 MB) admits a payload at the limit.
#[tokio::test]
async fn test_limits_default_body_admits_under_limit() {
    let app = Router::new()
        .route("/", post(echo_body))
        .layer(limits::default_body());

    // Just under the 2 MB limit.
    let payload = vec![0_u8; 1024 * 1024];
    let len = payload.len();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::CONTENT_LENGTH, len.to_string())
        .body(Body::from(payload))
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

/// `large_body()` (10 MB) admits a payload that `default_body()` would reject.
#[tokio::test]
async fn test_limits_large_body_admits_3mb() {
    let app = Router::new()
        .route("/", post(echo_body))
        .layer(limits::large_body());

    // 3 MB — would be rejected by default_body() (2 MB) but allowed by large_body() (10 MB).
    let payload = vec![0_u8; 3 * 1024 * 1024];
    let len = payload.len();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::CONTENT_LENGTH, len.to_string())
        .body(Body::from(payload))
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

/// `custom_body(N)` enforces exactly N bytes.
#[tokio::test]
async fn test_limits_custom_body_enforces_specified_limit() {
    let app = Router::new()
        .route("/", post(echo_body))
        .layer(limits::custom_body(1024));

    // 2 KB exceeds the 1 KB limit
    let payload = vec![0_u8; 2048];
    let len = payload.len();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::CONTENT_LENGTH, len.to_string())
        .body(Body::from(payload))
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// ============================================================================
// Timeout — 408 REQUEST_TIMEOUT after deadline
// ============================================================================

/// `quick_timeout()` (10 s) returns 408 when the handler runs longer than the
/// deadline. Uses `tokio::time::pause()` + `advance()` to control time
/// deterministically — no wall-clock sleeps.
#[tokio::test(start_paused = true)]
async fn test_timeout_quick_fires_after_deadline() {
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                // Sleep "longer than" the 10 s quick_timeout; with paused
                // time this only resolves once the test advances the clock.
                tokio::time::sleep(Duration::from_secs(11)).await;
                "ok"
            }),
        )
        .layer(timeout::quick_timeout());

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let pending = tokio::spawn(app.oneshot(request));

    // Advance just past the 10 s deadline. tower-http's TimeoutLayer wakes
    // and emits 408. The handler's 11 s sleep is still pending and gets
    // cancelled.
    tokio::time::advance(Duration::from_secs(11)).await;

    let response = pending
        .await
        .expect("join handle")
        .expect("response result");

    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
}

/// Handler that completes promptly returns 200 even with a long timeout.
#[tokio::test(start_paused = true)]
async fn test_timeout_long_admits_fast_handler() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(timeout::long_timeout()); // 120 s

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

/// `quick_timeout()` (10 s) admits a handler that completes within 5 s.
#[tokio::test(start_paused = true)]
async fn test_timeout_quick_admits_within_deadline() {
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "ok"
            }),
        )
        .layer(timeout::quick_timeout());

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("valid request");

    let pending = tokio::spawn(app.oneshot(request));

    // Advance past the handler's 5 s sleep but well before the 10 s deadline.
    tokio::time::advance(Duration::from_secs(6)).await;

    let response = pending
        .await
        .expect("join handle")
        .expect("response result");

    assert_eq!(response.status(), StatusCode::OK);
}

// ============================================================================
// Compression — Content-Encoding response header
// ============================================================================

/// `default_compression()` honors `Accept-Encoding: gzip`.
#[tokio::test]
async fn test_compression_default_honors_gzip() {
    let app = Router::new()
        .route("/", get(|| async { vec![b'A'; 4096] }))
        .layer(compression::default_compression());

    let request = Request::builder()
        .uri("/")
        .header(header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let encoding = response
        .headers()
        .get(header::CONTENT_ENCODING)
        .expect("should set Content-Encoding")
        .to_str()
        .expect("ASCII");
    assert_eq!(encoding, "gzip");
}

/// `gzip_only()` does NOT serve brotli even when the client prefers it,
/// because br/deflate/zstd are explicitly disabled.
#[tokio::test]
async fn test_compression_gzip_only_rejects_brotli() {
    let app = Router::new()
        .route("/", get(|| async { vec![b'A'; 4096] }))
        .layer(compression::gzip_only());

    let request = Request::builder()
        .uri("/")
        .header(header::ACCEPT_ENCODING, "br")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    // No br support — the layer must serve the response uncompressed
    // rather than emitting Content-Encoding: br.
    let encoding = response.headers().get(header::CONTENT_ENCODING);
    assert!(
        encoding != Some(&HeaderValue::from_static("br")),
        "gzip_only must not serve brotli; got {encoding:?}",
    );
}

/// `gzip_only()` serves gzip when the client accepts it.
#[tokio::test]
async fn test_compression_gzip_only_serves_gzip() {
    let app = Router::new()
        .route("/", get(|| async { vec![b'A'; 4096] }))
        .layer(compression::gzip_only());

    let request = Request::builder()
        .uri("/")
        .header(header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");

    let encoding = response
        .headers()
        .get(header::CONTENT_ENCODING)
        .expect("should set Content-Encoding")
        .to_str()
        .expect("ASCII");
    assert_eq!(encoding, "gzip");
}

/// `request_decompression()` decodes a gzipped request body before the handler
/// sees it.
#[tokio::test]
async fn test_request_decompression_inflates_gzipped_body() {
    let app = Router::new()
        .route("/", post(echo_body))
        .layer(compression::request_decompression());

    let plaintext = b"hello world".repeat(100);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&plaintext).expect("gzip write");
    let gzipped = encoder.finish().expect("gzip finish");

    assert!(
        gzipped.len() < plaintext.len(),
        "test fixture must actually be compressed",
    );

    let request = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(Body::from(gzipped))
        .expect("valid request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let received_len: usize = std::str::from_utf8(&body)
        .expect("ASCII length")
        .parse()
        .expect("parse usize");

    // The handler must have seen the inflated payload, not the gzipped one.
    assert_eq!(received_len, plaintext.len());
}
