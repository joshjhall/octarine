//! Shared type system for the Layer 3 `anonymize` module.
//!
//! This module defines the **single canonical vocabulary** shared by the
//! analyzer and anonymizer surfaces: detection results, operator
//! configuration, per-entity operator output, and the top-level engine
//! result. It is intentionally behavior-free — the [`crate::anonymize`]
//! engine and the individual operators are implemented separately and import
//! these types.
//!
//! # Design notes
//!
//! Octarine deliberately diverges from Presidio's type layout to avoid several
//! documented anti-patterns:
//!
//! - **One** [`RecognizerResult`], not two divergent copies. Presidio carries
//!   a separate analyzer and anonymizer `RecognizerResult` with different
//!   ordering semantics; round-tripping between them silently drops fields.
//! - [`OperatorConfig`] is **caller-immutable**. Presidio's engine mutates the
//!   caller's `params` dict to inject `entity_type`; octarine threads context
//!   separately so a caller's config is never modified.
//! - [`ConflictResolutionStrategy`] defines **all three** variants. Presidio's
//!   docstring references a `NONE` member that is missing from the enum body.
//!
//! # Span semantics
//!
//! All spans are **half-open**: `start` is inclusive, `end` is exclusive
//! (matching Rust slice and Python slice conventions). Two spans that merely
//! touch — e.g. `[0, 5)` and `[5, 10)` — do **not** intersect. Every span type
//! implements [`PiiSpan`], which provides the overlap algebra as default
//! methods so the semantics are defined exactly once.

use std::collections::HashMap;

use octarine_problem::{Problem, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Shared span algebra for every PII-bearing type in the anonymize pipeline.
///
/// Implementors expose their span via [`start`](PiiSpan::start),
/// [`end`](PiiSpan::end), and [`entity_type`](PiiSpan::entity_type); the
/// overlap methods are provided as default implementations so that
/// [`RecognizerResult`] and [`OperatorResult`] share **one** definition of
/// "intersects", "contains", etc.
///
/// Spans are half-open: `start` inclusive, `end` exclusive.
pub trait PiiSpan {
    /// Inclusive start offset of the span.
    fn start(&self) -> usize;

    /// Exclusive end offset of the span.
    fn end(&self) -> usize;

    /// The entity type label (e.g. `"US_SSN"`, `"EMAIL_ADDRESS"`).
    fn entity_type(&self) -> &str;

    /// Returns `true` if the two spans overlap by at least one position.
    ///
    /// Half-open semantics: touching spans (`self.end == other.start`) do not
    /// intersect.
    fn intersects<T: PiiSpan>(&self, other: &T) -> bool {
        self.start() < other.end() && other.start() < self.end()
    }

    /// Returns `true` if `self` fully contains `other`.
    fn contains<T: PiiSpan>(&self, other: &T) -> bool {
        self.start() <= other.start() && other.end() <= self.end()
    }

    /// Returns `true` if `self` is fully contained within `other`.
    fn contained_in<T: PiiSpan>(&self, other: &T) -> bool {
        other.start() <= self.start() && self.end() <= other.end()
    }

    /// Returns `true` if both spans cover exactly the same range.
    fn equal_indices<T: PiiSpan>(&self, other: &T) -> bool {
        self.start() == other.start() && self.end() == other.end()
    }

    /// Returns `true` if the spans conflict (overlap). Equivalent to
    /// [`intersects`](PiiSpan::intersects); named separately for call-site
    /// clarity in conflict-resolution code.
    fn has_conflict<T: PiiSpan>(&self, other: &T) -> bool {
        self.intersects(other)
    }
}

/// The single canonical detection result produced by the analyzer surface and
/// consumed by the anonymizer surface.
///
/// Unlike Presidio, there is exactly one `RecognizerResult` type; it carries
/// the analyzer-specific `analysis_explanation` and `recognition_metadata`
/// fields as `Option`s so nothing is lost when a result flows into the
/// anonymizer.
///
/// # Ordering
///
/// Results sort by `(start, end)` only — the `score` is excluded so that
/// ordering is total and consistent (`f64` has no total order). This is the
/// one and only sort semantics in the pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecognizerResult {
    /// Entity type label (e.g. `"US_SSN"`).
    pub entity_type: String,
    /// Inclusive start offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
    /// Detection confidence in `[0.0, 1.0]`.
    pub score: f64,
    /// Optional human-readable explanation of why this entity was detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_explanation: Option<String>,
    /// Optional recognizer metadata (recognizer name, identifier, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recognition_metadata: Option<HashMap<String, Value>>,
}

impl RecognizerResult {
    /// Creates a new detection result.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if `start > end` or if `score` is not a
    /// finite value within `[0.0, 1.0]`.
    pub fn new(
        entity_type: impl Into<String>,
        start: usize,
        end: usize,
        score: f64,
    ) -> Result<Self> {
        if start > end {
            return Err(Problem::Validation(format!(
                "RecognizerResult start ({start}) must not exceed end ({end})"
            )));
        }
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(Problem::Validation(format!(
                "RecognizerResult score ({score}) must be finite and within [0.0, 1.0]"
            )));
        }
        Ok(Self {
            entity_type: entity_type.into(),
            start,
            end,
            score,
            analysis_explanation: None,
            recognition_metadata: None,
        })
    }

    /// Attaches a human-readable explanation, returning `self` for chaining.
    #[must_use]
    pub fn with_explanation(mut self, explanation: impl Into<String>) -> Self {
        self.analysis_explanation = Some(explanation.into());
        self
    }

    /// Attaches recognizer metadata, returning `self` for chaining.
    #[must_use]
    pub fn with_metadata(mut self, metadata: HashMap<String, Value>) -> Self {
        self.recognition_metadata = Some(metadata);
        self
    }
}

impl PiiSpan for RecognizerResult {
    fn start(&self) -> usize {
        self.start
    }
    fn end(&self) -> usize {
        self.end
    }
    fn entity_type(&self) -> &str {
        &self.entity_type
    }
}

impl Eq for RecognizerResult {}

impl PartialOrd for RecognizerResult {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RecognizerResult {
    /// Orders by `(start, end)` only. `score`, `entity_type`, and the optional
    /// fields are intentionally excluded to keep ordering total and stable.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.start, self.end).cmp(&(other.start, other.end))
    }
}

/// Per-entity operator configuration.
///
/// `params` is **never mutated** by the engine or operators. Context that the
/// engine needs to supply at apply time (such as the entity type) is threaded
/// separately rather than injected into this map, so a caller's config is
/// immutable from its perspective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorConfig {
    /// Name of the operator to apply (e.g. `"replace"`, `"mask"`, `"hash"`).
    pub operator_name: String,
    /// Operator-specific parameters. Read-only after construction.
    #[serde(default)]
    pub params: HashMap<String, Value>,
}

impl OperatorConfig {
    /// Creates a config with no parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if `operator_name` is empty.
    pub fn new(operator_name: impl Into<String>) -> Result<Self> {
        Self::with_params(operator_name, HashMap::new())
    }

    /// Creates a config with the given parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if `operator_name` is empty.
    pub fn with_params(
        operator_name: impl Into<String>,
        params: HashMap<String, Value>,
    ) -> Result<Self> {
        let operator_name = operator_name.into();
        if operator_name.is_empty() {
            return Err(Problem::Validation(
                "OperatorConfig operator_name must not be empty".to_string(),
            ));
        }
        Ok(Self {
            operator_name,
            params,
        })
    }

    /// Reads a string parameter by key, if present and string-typed.
    #[must_use]
    pub fn param_str(&self, key: &str) -> Option<&str> {
        self.params.get(key).and_then(Value::as_str)
    }
}

/// The result of applying an operator to a single detected entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorResult {
    /// Inclusive start offset in the output text.
    pub start: usize,
    /// Exclusive end offset in the output text.
    pub end: usize,
    /// Entity type label this result corresponds to.
    pub entity_type: String,
    /// The replacement text produced by the operator, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The name of the operator that produced this result, if recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
}

impl OperatorResult {
    /// Creates a new operator result.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if `start > end`.
    pub fn new(
        entity_type: impl Into<String>,
        start: usize,
        end: usize,
        text: Option<String>,
        operator: Option<String>,
    ) -> Result<Self> {
        if start > end {
            return Err(Problem::Validation(format!(
                "OperatorResult start ({start}) must not exceed end ({end})"
            )));
        }
        Ok(Self {
            start,
            end,
            entity_type: entity_type.into(),
            text,
            operator,
        })
    }
}

impl PiiSpan for OperatorResult {
    fn start(&self) -> usize {
        self.start
    }
    fn end(&self) -> usize {
        self.end
    }
    fn entity_type(&self) -> &str {
        &self.entity_type
    }
}

/// Top-level result of an anonymize or deanonymize run.
///
/// Serializes via `serde` like every other type here — there is no ad-hoc
/// JSON encoder.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineResult {
    /// The transformed output text, if the run produced one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Per-entity operator results, in output order.
    #[serde(default)]
    pub items: Vec<OperatorResult>,
}

impl EngineResult {
    /// Creates an empty result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the output text.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = Some(text.into());
    }

    /// Appends a per-entity operator result.
    pub fn add_item(&mut self, item: OperatorResult) {
        self.items.push(item);
    }
}

/// Direction of an operator pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorType {
    /// Forward direction: detect and transform PII.
    Anonymize,
    /// Reverse direction: restore previously transformed values.
    Deanonymize,
}

/// Strategy for resolving overlapping detection results before applying
/// operators.
///
/// All three variants are defined explicitly. The merge *logic* lives in the
/// engine (a later issue); this enum is the data definition only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolutionStrategy {
    /// Merge same-type spans that are similar or contained, then drop
    /// conflicted results. This is the default.
    #[default]
    MergeSimilarOrContained,
    /// Additionally trim partial overlaps, shrinking the lower-scoring span.
    RemoveIntersections,
    /// Apply no conflict resolution; pass results through untouched.
    None,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn rr(entity: &str, start: usize, end: usize) -> RecognizerResult {
        RecognizerResult::new(entity, start, end, 0.9).expect("valid result")
    }

    // ---- Constructor validation ------------------------------------------

    #[test]
    fn recognizer_result_rejects_inverted_span() {
        let err = RecognizerResult::new("X", 10, 5, 0.5);
        assert!(err.is_err());
    }

    #[test]
    fn recognizer_result_rejects_out_of_range_score() {
        assert!(RecognizerResult::new("X", 0, 1, 1.5).is_err());
        assert!(RecognizerResult::new("X", 0, 1, -0.1).is_err());
        assert!(RecognizerResult::new("X", 0, 1, f64::NAN).is_err());
        assert!(RecognizerResult::new("X", 0, 1, f64::INFINITY).is_err());
    }

    #[test]
    fn recognizer_result_accepts_boundary_scores() {
        assert!(RecognizerResult::new("X", 0, 1, 0.0).is_ok());
        assert!(RecognizerResult::new("X", 0, 1, 1.0).is_ok());
        assert!(RecognizerResult::new("X", 3, 3, 0.5).is_ok()); // zero-width OK
    }

    #[test]
    fn operator_config_rejects_empty_name() {
        assert!(OperatorConfig::new("").is_err());
        assert!(OperatorConfig::new("replace").is_ok());
    }

    #[test]
    fn operator_result_rejects_inverted_span() {
        assert!(OperatorResult::new("X", 5, 2, None, None).is_err());
        assert!(OperatorResult::new("X", 2, 5, None, None).is_ok());
    }

    // ---- Span algebra (half-open) ----------------------------------------

    #[test]
    fn disjoint_spans_do_not_intersect() {
        let a = rr("A", 0, 3);
        let b = rr("B", 5, 8);
        assert!(!a.intersects(&b));
        assert!(!a.has_conflict(&b));
    }

    #[test]
    fn touching_spans_do_not_intersect_half_open() {
        let a = rr("A", 0, 5);
        let b = rr("B", 5, 10);
        assert!(!a.intersects(&b));
        assert!(!b.intersects(&a));
    }

    #[test]
    fn partial_overlap_intersects_and_conflicts() {
        let a = rr("A", 0, 6);
        let b = rr("B", 4, 10);
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
        assert!(a.has_conflict(&b));
    }

    #[test]
    fn nested_spans_contain_and_are_contained() {
        let outer = rr("A", 0, 10);
        let inner = rr("B", 3, 6);
        assert!(outer.contains(&inner));
        assert!(inner.contained_in(&outer));
        assert!(!inner.contains(&outer));
        assert!(!outer.contained_in(&inner));
        // contains implies intersects
        assert!(outer.intersects(&inner));
    }

    #[test]
    fn identical_spans_are_equal_indices() {
        let a = rr("A", 2, 7);
        let b = rr("B", 2, 7);
        assert!(a.equal_indices(&b));
        assert!(a.contains(&b));
        assert!(a.contained_in(&b));
    }

    #[test]
    fn span_algebra_works_across_types() {
        let recog = rr("A", 0, 10);
        let op = OperatorResult::new("B", 3, 6, None, None).expect("valid");
        assert!(recog.contains(&op));
        assert!(op.contained_in(&recog));
    }

    // ---- Ordering --------------------------------------------------------

    #[test]
    fn recognizer_results_sort_by_start_then_end() {
        let mut v = [rr("A", 5, 9), rr("B", 0, 4), rr("C", 0, 2)];
        v.sort();
        let spans: Vec<(usize, usize)> = v.iter().map(|r| (r.start, r.end)).collect();
        assert_eq!(spans, vec![(0, 2), (0, 4), (5, 9)]);
    }

    // ---- serde round-trips -----------------------------------------------

    #[test]
    fn recognizer_result_round_trips_without_optional_fields() {
        let original = rr("US_SSN", 4, 15);
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: RecognizerResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, restored);
    }

    #[test]
    fn recognizer_result_round_trips_with_metadata() {
        let mut meta = HashMap::new();
        meta.insert("recognizer_name".to_string(), Value::String("ssn".into()));
        let original = rr("US_SSN", 4, 15)
            .with_explanation("matched SSN regex")
            .with_metadata(meta);
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: RecognizerResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, restored);
    }

    #[test]
    fn operator_config_round_trips() {
        let mut params = HashMap::new();
        params.insert("new_value".to_string(), Value::String("<REDACTED>".into()));
        let original = OperatorConfig::with_params("replace", params).expect("valid");
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: OperatorConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, restored);
        assert_eq!(restored.param_str("new_value"), Some("<REDACTED>"));
    }

    #[test]
    fn engine_result_round_trips() {
        let mut result = EngineResult::new();
        result.set_text("Hello <NAME>");
        result.add_item(
            OperatorResult::new(
                "PERSON",
                6,
                12,
                Some("<NAME>".into()),
                Some("replace".into()),
            )
            .expect("valid"),
        );
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: EngineResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
        assert_eq!(restored.items.len(), 1);
    }

    #[test]
    fn operator_type_round_trips_snake_case() {
        let json = serde_json::to_string(&OperatorType::Deanonymize).expect("serialize");
        assert_eq!(json, "\"deanonymize\"");
        let restored: OperatorType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, OperatorType::Deanonymize);
    }

    #[test]
    fn conflict_strategy_default_is_merge() {
        assert_eq!(
            ConflictResolutionStrategy::default(),
            ConflictResolutionStrategy::MergeSimilarOrContained
        );
    }

    #[test]
    fn all_conflict_strategy_variants_round_trip() {
        for variant in [
            ConflictResolutionStrategy::MergeSimilarOrContained,
            ConflictResolutionStrategy::RemoveIntersections,
            ConflictResolutionStrategy::None,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: ConflictResolutionStrategy =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }
}
