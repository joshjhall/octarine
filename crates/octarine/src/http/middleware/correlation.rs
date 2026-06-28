//! Correlation ID propagation middleware
//!
//! Wires the existing `traceparent` + `x-correlation-id` extraction helpers in
//! [`crate::observe::tracing`] into the HTTP layer so that:
//!
//! 1. Every inbound request is tagged with a correlation ID, taken from the
//!    `X-Correlation-ID`, `X-Request-ID`, or W3C `traceparent` header (in that
//!    priority order), or freshly generated when none is present.
//! 2. The id is established in a **task-local** scope for the duration of the
//!    request, so every `observe::Event` emitted inside the handler — across
//!    `await` points and worker-thread hops — automatically carries it.
//! 3. The response echoes the active correlation ID back to the caller via the
//!    `X-Correlation-ID` header and a chained W3C `traceparent`, letting
//!    downstream services and clients stitch the request chain across hops.
//!
//! # Security
//!
//! Inbound header values are accepted **only** when they parse as a UUID. The
//! underlying [`extract_from_headers`](crate::observe::tracing::extract_from_headers)
//! helper validates every candidate, so arbitrary header content can never reach
//! the correlation ID — closing log-injection and downstream header-smuggling
//! vectors. A present-but-invalid `X-Correlation-ID` is rejected (a fresh id is
//! generated) and a warning is logged **without** echoing the rejected value.
//!
//! # Relationship to [`RequestIdLayer`](super::RequestIdLayer)
//!
//! `RequestIdLayer` sets the correlation ID in **thread-local** storage and only
//! understands `X-Request-ID`. `CorrelationLayer` is the richer option: it also
//! accepts `X-Correlation-ID` and W3C `traceparent`, scopes the id as
//! **task-local** (correct for async handlers on a multi-threaded runtime), and
//! emits a chained `traceparent` on the response. Use one or the other, not both.
//!
//! # Preferred Layer Order
//!
//! Mount `CorrelationLayer` outermost so every subsequent layer's events carry
//! the id (outermost listed first):
//!
//! 1. `CorrelationLayer` — correlation ID + traceparent (first, so all logs have it)
//! 2. `ObserveLayer` — request/response logging (inherits the id)
//! 3. `ContextLayer` — tenant / user / source IP
//! 4. `AuthLayer` — authentication (its failures are logged with the id)
//! 5. `RateLimitLayer` — typically per-route
//!
//! # Example
//!
//! ```rust
//! use axum::{Router, routing::get};
//! use octarine::http::middleware::CorrelationLayer;
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .layer(CorrelationLayer::new());
//! ```

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Request, Response, header::HeaderName},
};
use tower::{Layer, Service};
use uuid::Uuid;

use crate::observe::tracing::{extract_correlation_id, inject_to_headers};
use crate::observe::warn;
use crate::primitives::runtime as prim_runtime;

/// Header name for the correlation ID (canonical, echoed on responses).
pub static X_CORRELATION_ID: HeaderName = HeaderName::from_static("x-correlation-id");

/// Header name for the W3C trace context.
pub static TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");

/// Layer that propagates a correlation ID across the request lifecycle.
///
/// See the module-level documentation for behavior, security notes, and the
/// preferred ordering relative to the other middleware layers.
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::middleware::CorrelationLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(CorrelationLayer::new());
/// ```
#[derive(Debug, Clone, Default)]
pub struct CorrelationLayer {
    /// When `true`, also write the resolved id into the **request** headers as
    /// `X-Correlation-ID` (if absent) so downstream services receive it.
    propagate_to_request: bool,
}

impl CorrelationLayer {
    /// Create a new `CorrelationLayer` with default settings.
    ///
    /// By default the resolved id is propagated into the inbound request headers
    /// so that downstream services (reached from within the handler) inherit it.
    #[must_use]
    pub fn new() -> Self {
        Self {
            propagate_to_request: true,
        }
    }

    /// Control whether the resolved id is written into the inbound request
    /// headers (`X-Correlation-ID`) for downstream propagation.
    ///
    /// Disable this if a downstream client constructs its own outbound headers
    /// and you do not want the inbound request mutated.
    #[must_use]
    pub fn propagate_to_request(mut self, enable: bool) -> Self {
        self.propagate_to_request = enable;
        self
    }
}

impl<S> Layer<S> for CorrelationLayer {
    type Service = CorrelationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CorrelationService {
            inner,
            propagate_to_request: self.propagate_to_request,
        }
    }
}

/// Service that resolves, scopes, and echoes the correlation ID.
#[derive(Debug, Clone)]
pub struct CorrelationService<S> {
    inner: S,
    propagate_to_request: bool,
}

/// Build a case-preserving string view of the header map for the `HeaderLike`
/// extraction helpers. Header names are already lowercase in axum, and the
/// helpers query case-insensitively, so this is a faithful adapter.
fn headers_to_map(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect()
}

impl<S> Service<Request<Body>> for CorrelationService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        // Reject a present-but-invalid X-Correlation-ID. We log WITHOUT echoing
        // the rejected value to avoid log injection from attacker-controlled
        // header content.
        let raw_correlation = request
            .headers()
            .get(&X_CORRELATION_ID)
            .and_then(|v| v.to_str().ok());
        if let Some(raw) = raw_correlation
            && Uuid::parse_str(raw.trim()).is_err()
        {
            warn(
                "correlation",
                "Rejected invalid X-Correlation-ID header (not a UUID); generating a fresh id",
            );
        }

        // Extract the trace context. `extract_correlation_id` tries
        // X-Correlation-ID -> X-Request-ID -> traceparent (all UUID-validated)
        // and falls back to a fresh UUID when none is present/valid.
        let header_map = headers_to_map(request.headers());
        let correlation_id = extract_correlation_id(&header_map).correlation_id;

        // Optionally propagate the resolved id into the request headers so
        // downstream services reached from the handler inherit it.
        if self.propagate_to_request
            && let Ok(value) = HeaderValue::from_str(&correlation_id.to_string())
        {
            request
                .headers_mut()
                .insert(X_CORRELATION_ID.clone(), value);
        }

        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Scope the id as task-local so every observe::Event emitted during
            // request handling carries it, across await points and threads.
            let mut response =
                prim_runtime::with_correlation_id(correlation_id, inner.call(request)).await?;

            inject_correlation_response(response.headers_mut(), correlation_id);

            Ok(response)
        })
    }
}

/// Echo the correlation id into response headers: `X-Correlation-ID` plus a
/// chained W3C `traceparent`.
///
/// The canonical formatting (including the trace-id derived from the correlation
/// id, which keeps the trace chained across hops) is reused from
/// [`inject_to_headers`]; we copy only the correlation + traceparent headers so
/// we never clobber an `X-Request-ID` set by another layer.
fn inject_correlation_response(headers: &mut HeaderMap, correlation_id: Uuid) {
    let mut formatted: HashMap<String, String> = HashMap::new();
    inject_to_headers(&mut formatted, correlation_id);

    // `inject_to_headers` keys the map with the propagation module's own header
    // casing (e.g. `X-Correlation-ID`), so match case-insensitively against the
    // lowercase canonical names we want to copy. We copy only correlation +
    // traceparent so we never clobber an `X-Request-ID` set by another layer.
    for canonical in [&X_CORRELATION_ID, &TRACEPARENT] {
        if let Some(value) = formatted
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(canonical.as_str()))
            .map(|(_, value)| value)
            && let Ok(header_value) = HeaderValue::from_str(value)
        {
            headers.insert(canonical.clone(), header_value);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_layer_creation_defaults() {
        let layer = CorrelationLayer::new();
        assert!(layer.propagate_to_request);
    }

    #[test]
    fn test_propagate_to_request_toggle() {
        let layer = CorrelationLayer::new().propagate_to_request(false);
        assert!(!layer.propagate_to_request);
    }

    #[test]
    fn test_headers_to_map_skips_non_utf8() {
        let mut headers = HeaderMap::new();
        headers.insert(&X_CORRELATION_ID, HeaderValue::from_static("abc"));
        headers.insert(
            HeaderName::from_static("x-binary"),
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("bytes"),
        );

        let map = headers_to_map(&headers);
        assert_eq!(map.get("x-correlation-id"), Some(&"abc".to_string()));
        assert!(!map.contains_key("x-binary"));
    }

    #[test]
    fn test_inject_correlation_response_sets_headers() {
        let id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        inject_correlation_response(&mut headers, id);

        let echoed = headers
            .get(&X_CORRELATION_ID)
            .and_then(|v| v.to_str().ok())
            .expect("x-correlation-id set");
        assert_eq!(echoed, id.to_string());

        let traceparent = headers
            .get(&TRACEPARENT)
            .and_then(|v| v.to_str().ok())
            .expect("traceparent set");
        assert!(traceparent.starts_with("00-"));

        // We intentionally do not set X-Request-ID here (avoid clobbering
        // RequestIdLayer).
        assert!(headers.get("x-request-id").is_none());
    }
}
