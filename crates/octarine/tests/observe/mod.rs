//! Integration tests for the observe module
//!
//! These tests verify end-to-end behavior across observe components:
//! - Event creation and dispatch
//! - Writer implementations
//! - Async dispatch behavior
//! - PII detection through full pipeline
//! - Multi-tenant context isolation
//! - Context capture from thread-local/task-local storage
//! - Metrics export (Prometheus, StatsD)
//! - Tracing crate integration
//! - Audit builders and compliance tagging

mod async_dispatch;
mod audit_builders;
mod context_capture;
mod event_flow;
mod metrics_export;
mod pii_pipeline;
mod thresholds;
mod tracing_integration;
mod writer_file;
mod writer_memory;
