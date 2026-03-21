//! Tower middleware for HTTP servers
//!
//! Provides middleware layers that integrate with Octarine's observability
//! and context management.

#[cfg(feature = "auth")]
mod auth;
mod context;
mod metrics;
mod observe;
mod rate_limit;
mod request_id;
mod security;

#[cfg(feature = "auth")]
pub use auth::{ApiKeyValidator, AuthConfig, AuthLayer, AuthService, Claims};
pub use context::{ContextLayer, ContextService};
pub use metrics::{MetricsConfig, MetricsLayer, MetricsService};
// Re-export PathPattern from data layer for public API
pub use crate::data::network::PathPattern;
pub use observe::{ObserveConfig, ObserveLayer, ObserveService};
pub use rate_limit::{KeyStrategy, RateLimitConfig, RateLimitLayer, RateLimitService};
pub use request_id::{RequestIdLayer, RequestIdService};
pub use security::{FrameOptions, SecurityConfig, SecurityLayer, SecurityService};
