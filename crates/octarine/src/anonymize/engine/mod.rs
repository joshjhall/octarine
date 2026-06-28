//! The anonymizer engines — single-text and parallel batch.
//!
//! This module groups the two engine surfaces that apply operators to detected
//! spans:
//!
//! - [`AnonymizerEngine`] — the single-text orchestration surface. It takes one
//!   text plus its [`RecognizerResult`](crate::anonymize::RecognizerResult)
//!   detections and a per-entity operator map, resolves overlaps, and rewrites
//!   the text by applying the configured operator to each span (sync, plus a
//!   session-aware async path through the token vault).
//! - [`BatchAnonymizerEngine`] — anonymizes lists and nested
//!   [`serde_json::Value`] structures in parallel via `rayon`, built on top of
//!   the single-text engine. Output order matches input order; non-string JSON
//!   values pass through unchanged.
//!
//! `BatchAnonymizerEngine` is octarine's day-one win over Presidio's
//! `BatchAnonymizerEngine.anonymize_list`, which is a sequential `for` loop.

mod batch;
mod core;

pub use batch::BatchAnonymizerEngine;
pub use core::AnonymizerEngine;
