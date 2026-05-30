//! Anonymization operator and engine surface (Layer 3).
//!
//! This module is octarine's parity surface for Presidio's `AnonymizerEngine`:
//! it consumes detection results and applies configurable per-entity
//! transformations (replace, redact, mask, hash, encrypt, keep, custom, …) to
//! produce anonymized text plus an audit trail.
//!
//! # Status
//!
//! This is the foundational **type system** only. The engine and the
//! individual operators are implemented in follow-up work; everything they
//! share is defined here:
//!
//! - `RecognizerResult` — the single canonical detection result.
//! - `OperatorConfig` — caller-immutable per-entity operator configuration.
//! - `OperatorResult` / `EngineResult` — per-entity and top-level output.
//! - `OperatorType` — anonymize vs deanonymize direction.
//! - `ConflictResolutionStrategy` — overlap-resolution selector.
//! - `PiiSpan` — shared half-open span algebra (intersects, contains, …).
//!
//! All spans are half-open (`start` inclusive, `end` exclusive). See the type
//! definitions below for the full design rationale and the Presidio
//! anti-patterns this layout deliberately avoids.

mod types;

pub use types::{
    ConflictResolutionStrategy, EngineResult, OperatorConfig, OperatorResult, OperatorType,
    PiiSpan, RecognizerResult,
};
