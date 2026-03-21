//! Request ID middleware
//!
//! Generates unique request IDs for tracing requests through the system.
//! If a request already has an `X-Request-ID` header, it is preserved.
//! Otherwise, a new UUID is generated.
//!
//! The request ID is:
//! 1. Set in Octarine's context via `set_correlation_id()`
//! 2. Added to the response headers as `X-Request-ID`

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{HeaderValue, Request, Response, header::HeaderName},
};
use tower::{Layer, Service};
use uuid::Uuid;

use crate::primitives::runtime as prim_runtime;

/// Header name for request ID
pub static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Layer that adds request ID handling to a service.
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::RequestIdLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(RequestIdLayer::new());
/// ```
#[derive(Debug, Clone, Default)]
pub struct RequestIdLayer {
    /// Custom header name (defaults to X-Request-ID)
    header_name: Option<HeaderName>,
}

impl RequestIdLayer {
    /// Create a new `RequestIdLayer` with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a custom header name instead of `X-Request-ID`.
    #[must_use]
    pub fn with_header_name(mut self, name: HeaderName) -> Self {
        self.header_name = Some(name);
        self
    }
}

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdService {
            inner,
            header_name: self.header_name.clone(),
        }
    }
}

/// Service that handles request ID generation and propagation.
#[derive(Debug, Clone)]
pub struct RequestIdService<S> {
    inner: S,
    header_name: Option<HeaderName>,
}

impl<S> RequestIdService<S> {
    fn header_name(&self) -> &HeaderName {
        self.header_name.as_ref().unwrap_or(&X_REQUEST_ID)
    }
}

impl<S> Service<Request<Body>> for RequestIdService<S>
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
        let header_name = self.header_name().clone();

        // Extract existing request ID or generate new one
        // Try to parse as UUID, generate new one if invalid or missing
        let request_id: Uuid = request
            .headers()
            .get(&header_name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| Uuid::try_parse(s).ok())
            .unwrap_or_else(Uuid::new_v4);

        // Set in Octarine context for observability
        prim_runtime::set_correlation_id(request_id);

        let request_id_str = request_id.to_string();

        // Ensure request has the header (for downstream services)
        if !request.headers().contains_key(&header_name)
            && let Ok(value) = HeaderValue::from_str(&request_id_str)
        {
            request.headers_mut().insert(header_name.clone(), value);
        }

        let mut inner = self.inner.clone();

        Box::pin(async move {
            let mut response = inner.call(request).await?;

            // Add request ID to response headers
            if let Ok(value) = HeaderValue::from_str(&request_id_str) {
                response.headers_mut().insert(header_name, value);
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_creation() {
        let layer = RequestIdLayer::new();
        assert!(layer.header_name.is_none());
    }

    #[test]
    fn test_custom_header_name() {
        let custom = HeaderName::from_static("x-correlation-id");
        let layer = RequestIdLayer::new().with_header_name(custom.clone());
        assert_eq!(layer.header_name.as_ref(), Some(&custom));
    }
}
