//! Request body size limit presets
//!
//! Provides opinionated body size limits to prevent memory exhaustion attacks.
//!
//! # Presets
//!
//! | Preset | Size | Use Case |
//! |--------|------|----------|
//! | `default_body()` | 2 MB | Standard JSON API payloads |
//! | `large_body()` | 10 MB | Larger payloads, batch operations |
//! | `upload_body()` | 50 MB | File uploads |
//! | `ingestion_body()` | 100 MB | Bulk data ingestion |
//!
//! # Example
//!
//! ```rust
//! use axum::Router;
//! use octarine::http::presets::limits;
//!
//! let app: Router = Router::new()
//!     .layer(limits::default_body());
//! ```

pub use tower_http::limit::RequestBodyLimitLayer;

/// 2 MB - Default limit for standard JSON API payloads
const DEFAULT_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// 10 MB - Larger limit for batch operations
const LARGE_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// 50 MB - Limit for file uploads
const UPLOAD_BODY_LIMIT: usize = 50 * 1024 * 1024;

/// 100 MB - Limit for bulk data ingestion
const INGESTION_BODY_LIMIT: usize = 100 * 1024 * 1024;

/// Default body size limit (2 MB).
///
/// Suitable for standard JSON API payloads. Rejects requests with bodies
/// larger than 2 MB with a 413 Payload Too Large response.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::limits;
///
/// let app: Router = Router::new()
///     .layer(limits::default_body());
/// ```
#[must_use]
pub fn default_body() -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(DEFAULT_BODY_LIMIT)
}

/// Large body size limit (10 MB).
///
/// Suitable for batch operations and larger JSON payloads.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::limits;
///
/// let app: Router = Router::new()
///     .layer(limits::large_body());
/// ```
#[must_use]
pub fn large_body() -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(LARGE_BODY_LIMIT)
}

/// Upload body size limit (50 MB).
///
/// Suitable for file upload endpoints.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::limits;
///
/// let app: Router = Router::new()
///     .route("/upload", axum::routing::post(upload_handler))
///     .layer(limits::upload_body());
///
/// async fn upload_handler() {}
/// ```
#[must_use]
pub fn upload_body() -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(UPLOAD_BODY_LIMIT)
}

/// Ingestion body size limit (100 MB).
///
/// Suitable for bulk data ingestion endpoints where large payloads are expected.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::limits;
///
/// let app: Router = Router::new()
///     .route("/ingest", axum::routing::post(ingest_handler))
///     .layer(limits::ingestion_body());
///
/// async fn ingest_handler() {}
/// ```
#[must_use]
pub fn ingestion_body() -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(INGESTION_BODY_LIMIT)
}

/// Custom body size limit.
///
/// Use when the presets don't match your needs.
///
/// # Arguments
///
/// * `bytes` - Maximum body size in bytes
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::limits;
///
/// // 5 MB limit
/// let app: Router = Router::new()
///     .layer(limits::custom_body(5 * 1024 * 1024));
/// ```
#[must_use]
pub fn custom_body(bytes: usize) -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Construction smoke tests — confirm constructors do not panic on valid
    // inputs. RequestBodyLimitLayer exposes no public accessors, so behavioral
    // assertions (413 on oversized body, 200 on under-size body) live in
    // `tests/http/presets.rs` and exercise the layer via Router::oneshot().

    #[test]
    fn test_default_body_creates_layer() {
        let _layer = default_body();
    }

    #[test]
    fn test_large_body_creates_layer() {
        let _layer = large_body();
    }

    #[test]
    fn test_upload_body_creates_layer() {
        let _layer = upload_body();
    }

    #[test]
    fn test_ingestion_body_creates_layer() {
        let _layer = ingestion_body();
    }

    #[test]
    fn test_custom_body_creates_layer() {
        let _layer = custom_body(1024);
    }

    #[test]
    fn test_preset_sizes() {
        assert_eq!(DEFAULT_BODY_LIMIT, 2 * 1024 * 1024);
        assert_eq!(LARGE_BODY_LIMIT, 10 * 1024 * 1024);
        assert_eq!(UPLOAD_BODY_LIMIT, 50 * 1024 * 1024);
        assert_eq!(INGESTION_BODY_LIMIT, 100 * 1024 * 1024);
    }
}
