//! Tracing crate integration for distributed observability
//!
//! This module provides integration between the `tracing` ecosystem and the
//! observe module, enabling:
//!
//! - **ObserveLayer**: Forwards tracing events to observe for unified logging
//! - **Span Bridge**: Maps tracing spans to observe correlation IDs
//! - **HTTP Propagation**: Extract/inject trace context in HTTP headers
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │  Application Code                                    │
//! │  tracing::info!("msg")  /  observe::info("op","msg")│
//! └──────────────────────┬──────────────────────────────┘
//!                        │
//!        ┌───────────────▼───────────────┐
//!        │  tracing Subscriber            │
//!        │  (e.g., Registry)              │
//!        └───────────────┬───────────────┘
//!                        │
//!        ┌───────────────▼───────────────┐
//!        │  ObserveLayer                  │
//!        │  - Converts tracing events     │
//!        │  - Maps spans to correlation   │
//!        │  - Forwards to observe writers │
//!        └───────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use octarine::observe::tracing::{ObserveLayer, TracingConfig};
//! use tracing_subscriber::{layer::SubscriberExt, Registry};
//!
//! // Create a subscriber with ObserveLayer
//! let subscriber = Registry::default()
//!     .with(ObserveLayer::new(TracingConfig::default()));
//!
//! tracing::subscriber::set_global_default(subscriber)
//!     .expect("Failed to set subscriber");
//!
//! // Now tracing events are forwarded to observe
//! tracing::info!(operation = "startup", "Application started");
//! ```
//!
//! # HTTP Header Propagation
//!
//! For distributed tracing across services:
//!
//! ```rust,ignore
//! use octarine::tracing::{extract_from_headers, inject_to_headers};
//!
//! // Extract context from incoming request
//! let correlation_id = extract_from_headers(&request.headers());
//! if let Some(id) = correlation_id {
//!     octarine::observe::set_correlation_id(id);
//! }
//!
//! // Inject context for outgoing request
//! inject_to_headers(&mut request.headers_mut(), correlation_id);
//! ```

mod config;
mod layer;
mod propagation;

// Private submodule - re-export types at tracing level (three-layer API)
#[cfg(feature = "otel")]
mod otel;

pub use config::TracingConfig;
pub use layer::ObserveLayer;
pub use propagation::{
    HeaderLike, HeaderLikeMut, TraceContext, extract_correlation_id, extract_from_headers,
    inject_correlation_id, inject_to_headers,
};

// Re-export otel types at tracing level (three-layer API)
#[cfg(feature = "otel")]
pub use otel::{
    OtelConfig, OtelError, OtelExporter, export_event, init_otel, shutdown_otel, trace_id_to_uuid,
    uuid_to_span_id, uuid_to_trace_id,
};

/// Initialize tracing with the observe integration
///
/// This is a convenience function that sets up a tracing subscriber with
/// the ObserveLayer and optional console output.
///
/// # Example
///
/// ```rust,no_run
/// use octarine::observe::tracing::{init_tracing, TracingConfig};
///
/// init_tracing(TracingConfig::default());
///
/// tracing::info!(operation = "startup", "Application started");
/// ```
pub fn init_tracing(config: TracingConfig) {
    use tracing_subscriber::{Registry, layer::SubscriberExt, util::SubscriberInitExt};

    let subscriber = Registry::default().with(ObserveLayer::new(config));

    subscriber.init();
}

/// Initialize tracing with observe integration and console output
///
/// Combines ObserveLayer with tracing-subscriber's fmt layer for console output.
///
/// # Example
///
/// ```rust,no_run
/// use octarine::observe::tracing::{init_tracing_with_console, TracingConfig};
///
/// init_tracing_with_console(TracingConfig::default());
/// ```
pub fn init_tracing_with_console(config: TracingConfig) {
    use tracing_subscriber::{Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    let subscriber = Registry::default()
        .with(ObserveLayer::new(config))
        .with(fmt::layer());

    subscriber.init();
}
