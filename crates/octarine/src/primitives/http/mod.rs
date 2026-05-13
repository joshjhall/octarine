//! HTTP primitives (Layer 1)
//!
//! Pure HTTP-related utilities with no observe dependencies. Each function
//! takes string slices and returns plain values, keeping the module
//! framework-agnostic — callers in [`crate::http`] convert from
//! `axum::http::HeaderValue` (or similar) before calling in.
//!
//! # Submodules
//!
//! - [`request_id`] — Parse or generate a request-correlation UUID.
//! - [`headers`] — Parse forwarded-IP and Bearer-token headers.
//! - [`security`] — Build `Strict-Transport-Security` values, detect
//!   production/staging environments.
//! - [`routing`] — Match request paths against exclusion lists.
//!
//! # Architecture
//!
//! This is Layer 1 (primitives) — pure functions with no observe
//! dependencies. Layer 3 (`src/http/`) wraps these with Tower middleware,
//! Axum extractors, and observe instrumentation.

pub mod headers;
pub mod request_id;
pub mod routing;
pub mod security;
