//! Request timeout presets
//!
//! Provides opinionated timeout configurations to prevent slowloris attacks
//! and resource exhaustion from slow clients.
//!
//! # Presets
//!
//! | Preset | Timeout | Use Case |
//! |--------|---------|----------|
//! | `default_timeout()` | 30s | Standard API requests |
//! | `quick_timeout()` | 10s | Fast operations (health checks, simple queries) |
//! | `long_timeout()` | 120s | Long-running operations (reports, exports) |
//! | `upload_timeout()` | 300s | File uploads |
//!
//! # Example
//!
//! ```rust
//! use axum::Router;
//! use octarine::http::presets::timeout;
//!
//! let app: Router = Router::new()
//!     .layer(timeout::default_timeout());
//! ```

use std::time::Duration;

use http::StatusCode;
pub use tower_http::timeout::TimeoutLayer;

/// 30 seconds - Default timeout for standard API requests
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// 10 seconds - Quick timeout for fast operations
const QUICK_TIMEOUT: Duration = Duration::from_secs(10);

/// 120 seconds (2 minutes) - Long timeout for complex operations
const LONG_TIMEOUT: Duration = Duration::from_secs(120);

/// 300 seconds (5 minutes) - Extended timeout for file uploads
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Default request timeout (30 seconds).
///
/// Suitable for standard API requests. Requests taking longer than 30 seconds
/// will receive a 408 Request Timeout response.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::timeout;
///
/// let app: Router = Router::new()
///     .layer(timeout::default_timeout());
/// ```
#[must_use]
pub fn default_timeout() -> TimeoutLayer {
    TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, DEFAULT_TIMEOUT)
}

/// Quick request timeout (10 seconds).
///
/// Suitable for fast operations like health checks and simple queries.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::timeout;
///
/// let app: Router = Router::new()
///     .route("/health", axum::routing::get(health))
///     .layer(timeout::quick_timeout());
///
/// async fn health() -> &'static str { "ok" }
/// ```
#[must_use]
pub fn quick_timeout() -> TimeoutLayer {
    TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, QUICK_TIMEOUT)
}

/// Long request timeout (2 minutes).
///
/// Suitable for long-running operations like report generation and data exports.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::timeout;
///
/// let app: Router = Router::new()
///     .route("/report", axum::routing::get(generate_report))
///     .layer(timeout::long_timeout());
///
/// async fn generate_report() {}
/// ```
#[must_use]
pub fn long_timeout() -> TimeoutLayer {
    TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, LONG_TIMEOUT)
}

/// Upload request timeout (5 minutes).
///
/// Suitable for file upload endpoints where large files may take time to transfer.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::timeout;
///
/// let app: Router = Router::new()
///     .route("/upload", axum::routing::post(upload))
///     .layer(timeout::upload_timeout());
///
/// async fn upload() {}
/// ```
#[must_use]
pub fn upload_timeout() -> TimeoutLayer {
    TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, UPLOAD_TIMEOUT)
}

/// Custom request timeout.
///
/// Use when the presets don't match your needs.
///
/// # Arguments
///
/// * `duration` - Maximum request duration
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use axum::Router;
/// use octarine::http::presets::timeout;
///
/// // 45 second timeout
/// let app: Router = Router::new()
///     .layer(timeout::custom_timeout(Duration::from_secs(45)));
/// ```
#[must_use]
pub fn custom_timeout(duration: Duration) -> TimeoutLayer {
    TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_timeout_creates_layer() {
        let _layer = default_timeout();
    }

    #[test]
    fn test_quick_timeout_creates_layer() {
        let _layer = quick_timeout();
    }

    #[test]
    fn test_long_timeout_creates_layer() {
        let _layer = long_timeout();
    }

    #[test]
    fn test_upload_timeout_creates_layer() {
        let _layer = upload_timeout();
    }

    #[test]
    fn test_custom_timeout_creates_layer() {
        let _layer = custom_timeout(Duration::from_secs(60));
    }

    #[test]
    fn test_preset_durations() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
        assert_eq!(QUICK_TIMEOUT, Duration::from_secs(10));
        assert_eq!(LONG_TIMEOUT, Duration::from_secs(120));
        assert_eq!(UPLOAD_TIMEOUT, Duration::from_secs(300));
    }
}
