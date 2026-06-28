//! The anonymizer engines — single-text and parallel batch (both directions).
//!
//! This module groups the engine surfaces that apply operators to detected
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
//! - [`BatchDeanonymizeEngine`] — the symmetric reverse surface:
//!   `deanonymize_list` / `deanonymize_dict` reverse anonymized lists and nested
//!   dicts in parallel through the sync engine path, with per-item (lenient) or
//!   fail-fast (strict) error semantics.
//!
//! `BatchAnonymizerEngine` is octarine's day-one win over Presidio's
//! `BatchAnonymizerEngine.anonymize_list`, which is a sequential `for` loop, and
//! `BatchDeanonymizeEngine` has no Presidio counterpart at all — its
//! `DeanonymizeEngine` is single-text only.

mod batch;
mod core;

pub use batch::{BatchAnonymizerEngine, BatchDeanonymizeEngine};
pub use core::AnonymizerEngine;
