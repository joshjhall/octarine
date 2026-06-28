//! Integration tests for the served `/metrics` Prometheus endpoint.
//!
//! These exercise the `octarine::http::presets::metrics()` preset end-to-end
//! through `Router::oneshot()`, confirming the wiring an operator relies on:
//! the route serves, the `Content-Type` matches the Prometheus exposition
//! spec exactly, the body parses as valid Prometheus text, and an
//! uninitialized exporter degrades to a structured `503` rather than panicking.

#![allow(clippy::panic, clippy::expect_used)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use http_body_util::BodyExt;
use octarine::http::handlers::{MetricsState, metrics_handler};
use octarine::http::presets::metrics;
use tower::ServiceExt;

/// `Router::new().merge(metrics())` serves `/metrics` with status 200 and the
/// exact Prometheus content type.
#[tokio::test]
async fn test_preset_serves_metrics_with_prometheus_content_type() {
    let app = Router::new().merge(metrics::metrics());

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
        "text/plain; version=0.0.4",
    );
}

/// An uninitialized exporter answers `503` with the shared structured error
/// envelope instead of panicking.
#[tokio::test]
async fn test_uninitialized_exporter_returns_503_envelope() {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(MetricsState::uninitialized());

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
    assert!(
        json.pointer("/error/message")
            .and_then(|v| v.as_str())
            .is_some_and(|m| m.contains("not initialized")),
        "expected a descriptive message, got: {json}",
    );
}

/// Recording a known counter, gauge, and histogram produces a body that the
/// `prometheus-parse` crate accepts as valid Prometheus text exposition.
///
/// Requires the `testing` feature for `flush_for_testing()`, which drains the
/// async metric queue so the snapshot is deterministic.
#[cfg(feature = "testing")]
#[tokio::test]
async fn test_recorded_metrics_parse_as_prometheus_text() {
    use std::sync::atomic::{AtomicU64, Ordering};

    use octarine::observe::metrics::{MetricName, flush_for_testing, gauge, increment_by, record};
    use prometheus_parse::Scrape;

    // Unique suffix keeps this test isolated from the shared global registry.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let suffix = COUNTER.fetch_add(1, Ordering::SeqCst);
    let counter = format!("scrape.requests.{suffix}");
    let gauge_name = format!("scrape.queue.{suffix}");
    let histo = format!("scrape.latency.{suffix}");

    // Record and flush on a dedicated OS thread: `flush_for_testing()` blocks
    // on a oneshot channel, which panics if called inside this `#[tokio::test]`
    // runtime. The metric registry is process-global, so the flushed state is
    // visible to the request issued below.
    {
        let (counter, gauge_name, histo) = (counter.clone(), gauge_name.clone(), histo.clone());
        std::thread::spawn(move || {
            increment_by(MetricName::new(&counter).expect("valid name"), 7);
            gauge(MetricName::new(&gauge_name).expect("valid name"), 42);
            record(MetricName::new(&histo).expect("valid name"), 0.25);
            flush_for_testing();
        })
        .join()
        .expect("record thread");
    }

    let app = Router::new().merge(metrics::metrics());
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

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let body = String::from_utf8(bytes.to_vec()).expect("utf-8 body");

    // The endpoint must produce parseable Prometheus text exposition.
    let lines = body.lines().map(|l| Ok(l.to_string()));
    let scrape = Scrape::parse(lines).expect("body parses as Prometheus text");

    // Dots are normalized to underscores in the rendered names.
    let counter_metric = counter.replace('.', "_");
    let gauge_metric = gauge_name.replace('.', "_");
    let histo_metric = histo.replace('.', "_");

    assert!(
        scrape.samples.iter().any(|s| s.metric == counter_metric),
        "counter {counter_metric} missing from scrape: {body}",
    );
    assert!(
        scrape.samples.iter().any(|s| s.metric == gauge_metric),
        "gauge {gauge_metric} missing from scrape: {body}",
    );
    // Histograms render as `<name>_bucket` / `_sum` / `_count` series.
    assert!(
        scrape
            .samples
            .iter()
            .any(|s| s.metric.starts_with(&histo_metric)),
        "histogram {histo_metric} missing from scrape: {body}",
    );
}
