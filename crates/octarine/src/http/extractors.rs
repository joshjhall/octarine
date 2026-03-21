//! Axum extractors for Octarine context
//!
//! These extractors allow handlers to access context values set by
//! the middleware layers (`RequestIdLayer`, `ContextLayer`).
//!
//! # Example
//!
//! ```rust
//! use axum::{Router, routing::get};
//! use octarine::http::{
//!     CorrelationId, Tenant, SourceIp, RequestIdLayer, ContextLayer,
//! };
//!
//! async fn handler(
//!     CorrelationId(request_id): CorrelationId,
//!     Tenant(tenant): Tenant,
//!     SourceIp(ip): SourceIp,
//! ) -> String {
//!     format!(
//!         "request_id={}, tenant={:?}, ip={:?}",
//!         request_id, tenant, ip
//!     )
//! }
//!
//! let app: Router = Router::new()
//!     .route("/", get(handler))
//!     .layer(RequestIdLayer::new())
//!     .layer(ContextLayer::new());
//! ```

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use uuid::Uuid;

use crate::observe;
use crate::primitives::runtime as prim_runtime;

/// Extractor for the correlation/request ID.
///
/// Returns the UUID set by `RequestIdLayer`. If no correlation ID is set,
/// extraction fails with a 500 error (indicates middleware misconfiguration).
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::{CorrelationId, RequestIdLayer};
///
/// async fn handler(CorrelationId(id): CorrelationId) -> String {
///     format!("Request ID: {}", id)
/// }
///
/// let app: Router = Router::new()
///     .route("/", get(handler))
///     .layer(RequestIdLayer::new());
/// ```
#[derive(Debug, Clone, Copy)]
pub struct CorrelationId(pub Uuid);

impl<S> FromRequestParts<S> for CorrelationId
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        prim_runtime::try_correlation_id()
            .map(CorrelationId)
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Missing correlation ID - ensure RequestIdLayer is configured",
            ))
    }
}

/// Extractor for the optional correlation/request ID.
///
/// Unlike `CorrelationId`, this never fails - it returns `None` if
/// no correlation ID is set.
#[derive(Debug, Clone, Copy)]
pub struct OptionalCorrelationId(pub Option<Uuid>);

impl<S> FromRequestParts<S> for OptionalCorrelationId
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalCorrelationId(prim_runtime::try_correlation_id()))
    }
}

/// Extractor for the tenant ID.
///
/// Returns `None` if no tenant header was present in the request.
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::{Tenant, ContextLayer};
///
/// async fn handler(Tenant(tenant): Tenant) -> String {
///     match tenant {
///         Some(id) => format!("Tenant: {}", id),
///         None => "No tenant".to_string(),
///     }
/// }
///
/// let app: Router = Router::new()
///     .route("/", get(handler))
///     .layer(ContextLayer::new());
/// ```
#[derive(Debug, Clone)]
pub struct Tenant(pub Option<String>);

impl<S> FromRequestParts<S> for Tenant
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Tenant(prim_runtime::tenant_id()))
    }
}

/// Extractor that requires a tenant ID.
///
/// Fails with 400 Bad Request if no tenant ID is present.
/// Use this for endpoints that require multi-tenant context.
#[derive(Debug, Clone)]
pub struct RequiredTenant(pub String);

impl<S> FromRequestParts<S> for RequiredTenant
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        prim_runtime::tenant_id().map(RequiredTenant).ok_or((
            StatusCode::BAD_REQUEST,
            "Missing required X-Tenant-ID header",
        ))
    }
}

/// Extractor for the source IP address.
///
/// Returns the client IP extracted by `ContextLayer` (from X-Forwarded-For
/// or connection info).
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::{SourceIp, ContextLayer};
///
/// async fn handler(SourceIp(ip): SourceIp) -> String {
///     match ip {
///         Some(addr) => format!("Client IP: {}", addr),
///         None => "Unknown IP".to_string(),
///     }
/// }
///
/// let app: Router = Router::new()
///     .route("/", get(handler))
///     .layer(ContextLayer::new());
/// ```
#[derive(Debug, Clone)]
pub struct SourceIp(pub Option<String>);

impl<S> FromRequestParts<S> for SourceIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(SourceIp(observe::get_source_ip()))
    }
}

/// Extractor for the user ID.
///
/// Returns the user ID if set (typically by authentication middleware
/// that runs after `ContextLayer`).
#[derive(Debug, Clone)]
pub struct UserId(pub Option<String>);

impl<S> FromRequestParts<S> for UserId
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(UserId(prim_runtime::user_id()))
    }
}

/// Extractor that requires an authenticated user.
///
/// Fails with 401 Unauthorized if no user ID is present.
/// Use this for endpoints that require authentication.
#[derive(Debug, Clone)]
pub struct Authenticated(pub String);

impl<S> FromRequestParts<S> for Authenticated
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        prim_runtime::user_id()
            .map(Authenticated)
            .ok_or((StatusCode::UNAUTHORIZED, "Authentication required"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_id_debug() {
        let id = Uuid::new_v4();
        let extractor = CorrelationId(id);
        assert!(format!("{:?}", extractor).contains(&id.to_string()));
    }

    #[test]
    fn test_tenant_debug() {
        let extractor = Tenant(Some("acme".to_string()));
        assert!(format!("{:?}", extractor).contains("acme"));
    }
}
