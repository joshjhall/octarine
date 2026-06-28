//! Built-in Axum request handlers
//!
//! This module provides ready-made handlers for standard operational
//! endpoints, so operators can mount them without hand-rolling glue. Each
//! handler is paired with a preset in [`crate::http::presets`] that mounts it
//! at the conventional URL.
//!
//! | Handler | Preset | Endpoint |
//! |---------|--------|----------|
//! | [`metrics`] | [`crate::http::presets::metrics`] | `GET /metrics` |

pub mod metrics;

pub use metrics::{MetricsState, metrics_handler};
