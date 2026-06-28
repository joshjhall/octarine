//! Prometheus `/metrics` scrape handler
//!
//! Wires the existing [`PrometheusExporter`] into an Axum handler so operators
//! can scrape octarine services directly. The matching
//! [`crate::http::presets::metrics`] preset mounts this handler at `/metrics`.
//!
//! # Behavior
//!
//! - **200**: renders the active metric registry in Prometheus text exposition
//!   format with `Content-Type: text/plain; version=0.0.4`.
//! - **503**: returned (never a panic) when the exporter is *not initialized*,
//!   using the same structured error envelope as the rest of the HTTP module —
//!   the operational "not ready" signal a scrape config expects.
//! - **500**: returned if an initialized exporter *fails to render* (an
//!   internal error, not a readiness state), via the standard
//!   [`crate::http::ProblemResponse`] mapping.
//!
//! # Example
//!
//! ```rust
//! use axum::Router;
//! use octarine::http::handlers::{MetricsState, metrics_handler};
//! use octarine::observe::metrics::PrometheusExporter;
//!
//! // `MetricsState::new(...)` serves 200; `MetricsState::uninitialized()`
//! // (and `MetricsState::default()`) serve 503 until an exporter is wired.
//! let app: Router = Router::new()
//!     .route("/metrics", axum::routing::get(metrics_handler))
//!     .with_state(MetricsState::new(PrometheusExporter::default()));
//! ```

use axum::{
    Json,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::http::error::{ErrorBody, ErrorInfo, ProblemResponse};
use crate::observe::metrics::PrometheusExporter;
use crate::primitives::runtime as prim_runtime;

/// Prometheus exposition `Content-Type`, per the text format 0.0.4 spec.
///
/// Prometheus scrapers key off this exact value, so it is emitted verbatim
/// rather than the `text/plain; charset=utf-8` Axum would default to.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Shared state for the [`metrics_handler`].
///
/// Holds the [`PrometheusExporter`] that renders the active metric registry.
/// The exporter is optional: a `None` value models an *uninitialized* metrics
/// pipeline and causes the handler to answer `503` rather than serve an empty
/// or misleading body. The [`crate::http::presets::metrics`] preset always
/// injects an initialized exporter.
#[derive(Debug, Clone, Default)]
pub struct MetricsState {
    exporter: Option<PrometheusExporter>,
}

impl MetricsState {
    /// Create state with an initialized exporter (handler serves `200`).
    #[must_use]
    pub fn new(exporter: PrometheusExporter) -> Self {
        Self {
            exporter: Some(exporter),
        }
    }

    /// Create state with no exporter (handler answers `503`).
    ///
    /// Useful for wiring the route before the metrics pipeline is configured,
    /// so scrapers receive a clear "not ready" signal instead of a 404.
    #[must_use]
    pub fn uninitialized() -> Self {
        Self { exporter: None }
    }
}

/// Axum handler that serves the Prometheus text exposition.
///
/// Snapshots the active metric registry through the configured
/// [`PrometheusExporter`] and returns the rendered body with the Prometheus
/// `Content-Type`. Never panics: an absent exporter yields `503` (the "not
/// ready" signal Prometheus retries on its next scrape), and a render failure
/// yields `500` via the standard [`ProblemResponse`] mapping.
pub async fn metrics_handler(State(state): State<MetricsState>) -> Response {
    let Some(exporter) = state.exporter else {
        return unavailable("metrics exporter not initialized");
    };

    match exporter.render() {
        Ok(body) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
            )],
            body,
        )
            .into_response(),
        // A render failure is logged via the standard ProblemResponse path
        // (500) — distinct from "not initialized", which is the operational
        // 503 the scrape config expects.
        Err(problem) => ProblemResponse::from(problem).into_response(),
    }
}

/// Build a `503 Service Unavailable` response using the shared HTTP error
/// envelope, so scrapers and dashboards see the same structured body shape as
/// every other octarine error.
fn unavailable(message: &str) -> Response {
    let body = ErrorBody {
        error: ErrorInfo {
            code: "service_unavailable",
            message: message.to_string(),
            request_id: prim_runtime::try_correlation_id().map(|id| id.to_string()),
        },
    };

    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::{Router, http::StatusCode, http::header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    fn router(state: MetricsState) -> Router {
        Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(state)
    }

    /// An uninitialized exporter yields 503 (not a panic, not a 404).
    #[tokio::test]
    async fn test_uninitialized_returns_503() {
        let app = router(MetricsState::uninitialized());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        // The 503 must carry the shared structured error envelope, not an
        // empty body — dashboards key off `error.code`.
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON envelope");
        assert_eq!(
            json.pointer("/error/code").and_then(|v| v.as_str()),
            Some("service_unavailable"),
        );
    }

    /// `MetricsState::default()` is equivalent to `uninitialized()` (serves
    /// 503), guarding the doc example's stated behavior.
    #[tokio::test]
    async fn test_default_state_returns_503() {
        let app = router(MetricsState::default());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// An initialized exporter serves 200 with the exact Prometheus
    /// `Content-Type`.
    #[tokio::test]
    async fn test_initialized_sets_prometheus_content_type() {
        let app = router(MetricsState::new(PrometheusExporter::default()));

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
