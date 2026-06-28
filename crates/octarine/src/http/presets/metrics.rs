//! Prometheus `/metrics` scrape preset
//!
//! Mounts the [`crate::http::handlers::metrics_handler`] at the conventional
//! `/metrics` URL so operators can wire a scrapable endpoint in one line,
//! instead of plumbing the [`PrometheusExporter`] into a hand-rolled handler.
//!
//! The preset deliberately applies **no** auth, observe, or rate-limit layers —
//! scrapers expect an uninstrumented endpoint, and instrumenting `/metrics`
//! would pollute the very metrics being served.
//!
//! # Access control
//!
//! This preset does **not** restrict access, and the octarine middleware
//! layers do not exclude `/metrics` for you: `AuthConfig`, `RateLimitConfig`,
//! `ObserveConfig`, and `MetricsConfig` all start with an **empty**
//! exclude-path list. If you apply any of those layers globally, you must
//! explicitly call `.exclude_paths(["/metrics"])` on their config — otherwise
//! scrapers receive `401`/`429` and monitoring breaks. Conversely, the
//! exposition body reveals internal metric names and values, so restrict
//! access at the network layer (or add an auth layer scoped to this router)
//! before exposing it beyond a trusted scrape network.
//!
//! # Example
//!
//! ```rust
//! use axum::Router;
//! use octarine::http::presets::metrics;
//!
//! let app: Router = Router::new().merge(metrics::metrics());
//! ```
//!
//! [`PrometheusExporter`]: crate::observe::metrics::PrometheusExporter

use axum::{Router, routing::get};

use crate::http::handlers::{MetricsState, metrics_handler};
use crate::observe::metrics::{PrometheusConfig, PrometheusExporter};

/// Mount a Prometheus scrape endpoint at `GET /metrics`.
///
/// Uses a default [`PrometheusExporter`], which renders the active global
/// metric registry. Merge the returned router into your application:
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::metrics;
///
/// let app: Router = Router::new().merge(metrics::metrics());
/// ```
pub fn metrics() -> Router {
    with_config(PrometheusConfig::default())
}

/// Mount a Prometheus scrape endpoint at `GET /metrics` with a custom
/// [`PrometheusConfig`] (namespace, subsystem, default labels).
///
/// ```rust
/// use axum::Router;
/// use octarine::http::presets::metrics;
/// use octarine::observe::metrics::PrometheusConfig;
///
/// let app: Router = Router::new()
///     .merge(metrics::with_config(PrometheusConfig::new().namespace("myapp")));
/// ```
pub fn with_config(config: PrometheusConfig) -> Router {
    let state = MetricsState::new(PrometheusExporter::new(config));
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    use super::*;

    /// The preset serves 200 at `/metrics` with the Prometheus content type.
    #[tokio::test]
    async fn test_metrics_preset_serves_200() {
        let app = Router::new().merge(metrics());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content-type header"),
            "text/plain; version=0.0.4"
        );
    }

    /// `with_config()` (custom namespace) also serves 200 with the Prometheus
    /// content type — it is the only entry point for namespaced exposition.
    #[tokio::test]
    async fn test_with_config_serves_200() {
        let app = Router::new().merge(with_config(PrometheusConfig::new().namespace("myapp")));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content-type header"),
            "text/plain; version=0.0.4"
        );
    }
}
