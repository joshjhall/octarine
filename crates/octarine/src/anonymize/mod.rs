//! Anonymization operator and engine surface (Layer 3).
//!
//! This module is octarine's parity surface for Presidio's `AnonymizerEngine`:
//! it consumes detection results and applies configurable per-entity
//! transformations (replace, redact, mask, hash, encrypt, keep, custom, …) to
//! produce anonymized text plus an audit trail.
//!
//! # Components
//!
//! - `RecognizerResult` — the single canonical detection result.
//! - `OperatorConfig` — caller-immutable per-entity operator configuration.
//! - `OperatorResult` / `EngineResult` — per-entity and top-level output.
//! - `OperatorType` — anonymize vs deanonymize direction.
//! - `ConflictResolutionStrategy` — overlap-resolution selector.
//! - `PiiSpan` — shared half-open span algebra (intersects, contains, …).
//! - `Operator` — the transformation trait every operator implements.
//! - `AnonymizerEngine` — applies operators to detected spans with conflict
//!   resolution and offset tracking.
//! - `Replace` / `Redact` — the stateless built-in operators. `Custom` wraps a
//!   caller-supplied closure (`Fn(&str) -> Result<String>`) for one-off
//!   transforms and stateful pseudonymization. Further operators (mask, hash,
//!   encrypt, keep) land as follow-up work under the `anonymize/` umbrella.
//!
//! All spans are half-open (`start` inclusive, `end` exclusive). See the type
//! definitions for the full design rationale and the Presidio anti-patterns
//! this layout deliberately avoids.
//!
//! # Quick start
//!
//! ```
//! use std::collections::HashMap;
//! use octarine::anonymize::{anonymize, OperatorConfig, RecognizerResult};
//!
//! let mut operators = HashMap::new();
//! operators.insert("US_SSN".to_string(), OperatorConfig::new("redact")?);
//!
//! let results = vec![RecognizerResult::new("US_SSN", 4, 15, 0.95)?];
//! let out = anonymize("SSN 123-45-6789.", results, &operators)?;
//! assert_eq!(out.text.as_deref(), Some("SSN ."));
//! # Ok::<(), octarine_problem::Problem>(())
//! ```

mod engine;
mod operator;
mod operators;
mod shortcuts;
mod types;

pub use engine::AnonymizerEngine;
pub use operator::Operator;
pub use operators::{Custom, Redact, Replace};
pub use shortcuts::{anonymize, redact_all};
pub use types::{
    ConflictResolutionStrategy, EngineResult, OperatorConfig, OperatorResult, OperatorType,
    PiiSpan, RecognizerResult,
};
