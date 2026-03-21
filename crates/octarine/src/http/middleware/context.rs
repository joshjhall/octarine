//! Context extraction middleware
//!
//! Extracts contextual information from HTTP headers and sets them in
//! Octarine's observability context. This includes:
//!
//! - Tenant ID (from `X-Tenant-ID` header)
//! - Source IP (from `X-Forwarded-For` or connection info)
//! - User ID (from `X-User-ID` header, typically set by auth middleware)
//!
//! All extracted values are automatically included in Octarine log events.

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, Response, header::HeaderName},
};
use tower::{Layer, Service};

use crate::observe;
use crate::primitives::runtime as prim_runtime;

/// Header name for tenant ID
pub static X_TENANT_ID: HeaderName = HeaderName::from_static("x-tenant-id");

/// Header name for user ID
pub static X_USER_ID: HeaderName = HeaderName::from_static("x-user-id");

/// Header name for forwarded IP
pub static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Header name for real IP (common in nginx)
pub static X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// Layer that extracts context from HTTP headers.
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::ContextLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(ContextLayer::new());
/// ```
#[derive(Debug, Clone, Default)]
pub struct ContextLayer {
    /// Custom header name for tenant ID
    tenant_header: Option<HeaderName>,
    /// Custom header name for user ID
    user_header: Option<HeaderName>,
    /// Trust X-Forwarded-For header (only enable behind trusted proxy)
    trust_forwarded_for: bool,
}

impl ContextLayer {
    /// Create a new `ContextLayer` with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a custom header name for tenant ID instead of `X-Tenant-ID`.
    #[must_use]
    pub fn with_tenant_header(mut self, name: HeaderName) -> Self {
        self.tenant_header = Some(name);
        self
    }

    /// Use a custom header name for user ID instead of `X-User-ID`.
    #[must_use]
    pub fn with_user_header(mut self, name: HeaderName) -> Self {
        self.user_header = Some(name);
        self
    }

    /// Trust `X-Forwarded-For` header for source IP extraction.
    ///
    /// # Security Warning
    ///
    /// Only enable this when running behind a trusted reverse proxy that
    /// sets this header. Untrusted clients can spoof this header.
    #[must_use]
    pub fn trust_forwarded_for(mut self, trust: bool) -> Self {
        self.trust_forwarded_for = trust;
        self
    }
}

impl<S> Layer<S> for ContextLayer {
    type Service = ContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ContextService {
            inner,
            tenant_header: self.tenant_header.clone(),
            user_header: self.user_header.clone(),
            trust_forwarded_for: self.trust_forwarded_for,
        }
    }
}

/// Service that extracts context from HTTP headers.
#[derive(Debug, Clone)]
pub struct ContextService<S> {
    inner: S,
    tenant_header: Option<HeaderName>,
    user_header: Option<HeaderName>,
    trust_forwarded_for: bool,
}

impl<S> ContextService<S> {
    fn tenant_header(&self) -> &HeaderName {
        self.tenant_header.as_ref().unwrap_or(&X_TENANT_ID)
    }

    fn user_header(&self) -> &HeaderName {
        self.user_header.as_ref().unwrap_or(&X_USER_ID)
    }

    /// Extract source IP from request headers or connection info.
    fn extract_source_ip(&self, request: &Request<Body>) -> Option<String> {
        // Try X-Forwarded-For first (if trusted)
        if self.trust_forwarded_for {
            if let Some(forwarded) = request
                .headers()
                .get(&X_FORWARDED_FOR)
                .and_then(|v| v.to_str().ok())
            {
                // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
                // The first one is the original client
                if let Some(client_ip) = forwarded.split(',').next() {
                    return Some(client_ip.trim().to_string());
                }
            }

            // Try X-Real-IP (nginx convention)
            if let Some(real_ip) = request
                .headers()
                .get(&X_REAL_IP)
                .and_then(|v| v.to_str().ok())
            {
                return Some(real_ip.to_string());
            }
        }

        // Fall back to connection info
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
    }
}

impl<S> Service<Request<Body>> for ContextService<S>
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

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        // Clear any previous context to ensure request isolation
        // This is important when requests run sequentially on the same thread
        prim_runtime::clear_tenant_id();
        prim_runtime::clear_user_id();
        observe::clear_source_ip();

        // Extract tenant ID
        if let Some(tenant) = request
            .headers()
            .get(self.tenant_header())
            .and_then(|v| v.to_str().ok())
        {
            prim_runtime::set_tenant_id(tenant);
        }

        // Extract user ID
        if let Some(user_id) = request
            .headers()
            .get(self.user_header())
            .and_then(|v| v.to_str().ok())
        {
            prim_runtime::set_user_id(user_id);
        }

        // Extract source IP
        if let Some(source_ip) = self.extract_source_ip(&request) {
            observe::set_source_ip(&source_ip);
        }

        let mut inner = self.inner.clone();

        Box::pin(async move { inner.call(request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_creation() {
        let layer = ContextLayer::new();
        assert!(!layer.trust_forwarded_for);
    }

    #[test]
    fn test_custom_tenant_header() {
        let custom = HeaderName::from_static("x-org-id");
        let layer = ContextLayer::new().with_tenant_header(custom.clone());
        assert_eq!(layer.tenant_header.as_ref(), Some(&custom));
    }

    #[test]
    fn test_trust_forwarded_for() {
        let layer = ContextLayer::new().trust_forwarded_for(true);
        assert!(layer.trust_forwarded_for);
    }
}
