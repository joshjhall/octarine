//! CORS preset configurations
//!
//! Provides opinionated CORS configurations for common use cases.
//!
//! # Security Note
//!
//! CORS is a security feature. The permissive presets should only be used
//! in development. Always use `production()` with explicit origins in production.
//!
//! # Example
//!
//! ```rust
//! use axum::Router;
//! use octarine::http::presets::cors;
//!
//! // Development: allow all origins
//! let dev_app: Router = Router::new()
//!     .layer(cors::development());
//!
//! // Production: explicit allowed origins
//! let prod_app: Router = Router::new()
//!     .layer(cors::production(&["https://app.example.com", "https://admin.example.com"]));
//! ```

use std::time::Duration;

use http::{HeaderName, Method};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer, ExposeHeaders};

/// Standard headers allowed in CORS requests
const STANDARD_HEADERS: &[&str] = &[
    "content-type",
    "authorization",
    "x-request-id",
    "x-correlation-id",
    "x-tenant-id",
    "x-api-key",
];

/// Headers exposed in CORS responses
const EXPOSED_HEADERS: &[&str] = &[
    "x-request-id",
    "x-correlation-id",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
];

/// Standard methods allowed in CORS requests
const STANDARD_METHODS: &[Method] = &[
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::OPTIONS,
];

/// Parse header names from constant strings.
/// These are compile-time constants that are known to be valid.
fn parse_headers(headers: &[&str]) -> Vec<HeaderName> {
    headers
        .iter()
        .map(|h| {
            // SAFETY: These are compile-time constants defined in this module.
            // All header names are valid HTTP header names.
            #[allow(clippy::expect_used)]
            h.parse().expect("compile-time constant header name")
        })
        .collect()
}

/// Create a permissive CORS layer for development.
///
/// **WARNING**: Do not use in production. This allows:
/// - Any origin
/// - No credentials (incompatible with wildcard origin)
/// - All standard methods
/// - All standard headers
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::cors;
///
/// let app: Router = Router::new()
///     .layer(cors::development());
/// ```
pub fn development() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_credentials(false)
        .allow_methods(AllowMethods::list(STANDARD_METHODS.iter().cloned()))
        .allow_headers(AllowHeaders::list(parse_headers(STANDARD_HEADERS)))
        .expose_headers(ExposeHeaders::list(parse_headers(EXPOSED_HEADERS)))
        .max_age(Duration::from_secs(3600))
}

/// Create a restrictive CORS layer for production with explicit allowed origins.
///
/// This configuration:
/// - Only allows specified origins
/// - Allows credentials (cookies, auth headers)
/// - Allows standard API methods
/// - Allows standard headers including auth and correlation
/// - Exposes rate limit headers
///
/// # Arguments
///
/// * `origins` - List of allowed origin URLs (e.g., `["https://app.example.com"]`)
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::cors;
///
/// let app: Router = Router::new()
///     .layer(cors::production(&["https://app.example.com"]));
/// ```
///
/// # Panics
///
/// Panics if any origin URL is invalid.
pub fn production(origins: &[&str]) -> CorsLayer {
    let origins: Vec<_> = origins
        .iter()
        .map(|o| {
            // User-provided origins - panic is acceptable per documented contract
            #[allow(clippy::expect_used)]
            o.parse().expect("valid origin URL")
        })
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_methods(AllowMethods::list(STANDARD_METHODS.iter().cloned()))
        .allow_headers(AllowHeaders::list(parse_headers(STANDARD_HEADERS)))
        .expose_headers(ExposeHeaders::list(parse_headers(EXPOSED_HEADERS)))
        .max_age(Duration::from_secs(3600))
}

/// Create a CORS layer that only allows GET requests (read-only API).
///
/// Useful for public read-only APIs that don't need credentials.
///
/// # Arguments
///
/// * `origins` - List of allowed origin URLs, or empty for any origin
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::cors;
///
/// // Public read-only API
/// let app: Router = Router::new()
///     .layer(cors::read_only(&[]));
/// ```
///
/// # Panics
///
/// Panics if any origin URL is invalid.
pub fn read_only(origins: &[&str]) -> CorsLayer {
    let allow_origin = if origins.is_empty() {
        AllowOrigin::any()
    } else {
        let origins: Vec<_> = origins
            .iter()
            .map(|o| {
                // User-provided origins - panic is acceptable per documented contract
                #[allow(clippy::expect_used)]
                o.parse().expect("valid origin URL")
            })
            .collect();
        AllowOrigin::list(origins)
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(AllowMethods::list([Method::GET, Method::OPTIONS]))
        .allow_headers(AllowHeaders::list(parse_headers(&[
            "content-type",
            "x-request-id",
        ])))
        .expose_headers(ExposeHeaders::list(parse_headers(EXPOSED_HEADERS)))
        .max_age(Duration::from_secs(86400)) // 24 hours for read-only
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_development_creates_layer() {
        let _layer = development();
    }

    #[test]
    fn test_production_creates_layer() {
        let _layer = production(&["https://example.com"]);
    }

    #[test]
    fn test_production_multiple_origins() {
        let _layer = production(&["https://app.example.com", "https://admin.example.com"]);
    }

    #[test]
    fn test_read_only_any_origin() {
        let _layer = read_only(&[]);
    }

    #[test]
    fn test_read_only_specific_origins() {
        let _layer = read_only(&["https://example.com"]);
    }
}
