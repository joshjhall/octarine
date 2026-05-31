//! The anonymizer engine — applies operators to detected spans.
//!
//! [`AnonymizerEngine`] is the Layer 3 orchestration surface: it takes input
//! text plus a set of [`RecognizerResult`] detections and a per-entity operator
//! map, resolves any overlaps between detections, then rewrites the text by
//! applying the configured [`Operator`] to each span. The output carries both
//! the transformed text and an [`OperatorResult`] audit item per applied span.
//!
//! # Offset tracking
//!
//! The rewrite walks the input left to right, copying the unmodified gaps
//! between spans verbatim and pushing each operator's output in place. Output
//! offsets are read directly from the length of the text built so far, so a
//! replacement that is shorter, longer, empty, or the same length as the
//! original all stay correctly aligned with no delta arithmetic.

use std::collections::HashMap;

use octarine_problem::{Problem, Result};

use super::operators::{Mask, Redact, Replace};
use super::{
    ConflictResolutionStrategy, EngineResult, Operator, OperatorConfig, OperatorResult, PiiSpan,
    RecognizerResult,
};
use crate::observe;
use crate::observe::metrics::{increment_by, record};

crate::define_metrics! {
    anonymize_ms => "anonymize.engine.anonymize_ms",
    spans_operated => "anonymize.engine.spans_operated",
    errors => "anonymize.engine.errors",
}

/// The operator config key the engine falls back to for entities with no
/// explicit operator and no `DEFAULT` entry.
const DEFAULT_OPERATOR_KEY: &str = "DEFAULT";

/// Applies configurable per-entity operators to detected PII spans.
///
/// Construct with [`AnonymizerEngine::new`] (seeds the built-in `replace` and
/// `redact` operators) and optionally register more with
/// [`with_operator`](AnonymizerEngine::with_operator) or change overlap
/// handling with
/// [`with_conflict_strategy`](AnonymizerEngine::with_conflict_strategy).
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use octarine::anonymize::{AnonymizerEngine, OperatorConfig, RecognizerResult};
///
/// let engine = AnonymizerEngine::new();
/// let text = "Contact Jane at jane@example.com";
/// let results = vec![
///     RecognizerResult::new("PERSON", 8, 12, 0.9)?,
///     RecognizerResult::new("EMAIL_ADDRESS", 16, 32, 0.95)?,
/// ];
///
/// // No operator map → everything uses the default Replace (`<ENTITY_TYPE>`).
/// let out = engine.anonymize(text, results, &HashMap::new())?;
/// assert_eq!(out.text.as_deref(), Some("Contact <PERSON> at <EMAIL_ADDRESS>"));
/// assert_eq!(out.items.len(), 2);
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
pub struct AnonymizerEngine {
    registry: HashMap<String, Box<dyn Operator>>,
    conflict: ConflictResolutionStrategy,
    emit_events: bool,
}

impl std::fmt::Debug for AnonymizerEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&str> = self.registry.keys().map(String::as_str).collect();
        names.sort_unstable();
        f.debug_struct("AnonymizerEngine")
            .field("operators", &names)
            .field("conflict", &self.conflict)
            .field("emit_events", &self.emit_events)
            .finish()
    }
}

impl Default for AnonymizerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnonymizerEngine {
    /// Creates an engine with the built-in operators (`replace`, `redact`,
    /// `mask`) and the default
    /// [`ConflictResolutionStrategy::MergeSimilarOrContained`].
    #[must_use]
    pub fn new() -> Self {
        let mut engine = Self {
            registry: HashMap::new(),
            conflict: ConflictResolutionStrategy::default(),
            emit_events: true,
        };
        engine.register(Box::new(Replace));
        engine.register(Box::new(Redact));
        engine.register(Box::new(Mask));
        engine
    }

    /// Registers an operator, replacing any existing operator with the same
    /// [`operator_name`](Operator::operator_name).
    fn register(&mut self, operator: Box<dyn Operator>) {
        self.registry
            .insert(operator.operator_name().to_string(), operator);
    }

    /// Registers a custom operator, returning `self` for chaining.
    ///
    /// An operator whose name matches a built-in (`replace`, `redact`, `mask`)
    /// replaces it.
    #[must_use]
    pub fn with_operator(mut self, operator: Box<dyn Operator>) -> Self {
        self.register(operator);
        self
    }

    /// Sets the overlap-resolution strategy, returning `self` for chaining.
    #[must_use]
    pub fn with_conflict_strategy(mut self, strategy: ConflictResolutionStrategy) -> Self {
        self.conflict = strategy;
        self
    }

    /// Disables observe event/metric emission, returning `self` for chaining.
    ///
    /// Use in hot loops or recursive observe paths where instrumentation noise
    /// would be harmful.
    #[must_use]
    pub fn silent(mut self) -> Self {
        self.emit_events = false;
        self
    }

    /// Anonymizes `text` by applying the configured operator to each detected
    /// span.
    ///
    /// `operators` maps an entity type to the [`OperatorConfig`] to apply to it.
    /// An entity with no entry uses the `DEFAULT` key if present, otherwise the
    /// built-in `replace` operator (producing `<ENTITY_TYPE>`).
    ///
    /// Overlapping detections are reconciled per the engine's
    /// [`ConflictResolutionStrategy`] before any operator runs.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`] if an operator config names an unregistered
    /// operator, if an operator's [`validate`](Operator::validate) rejects its
    /// config, if a span lies outside `text` or on a non-char boundary, or if
    /// an operator's [`operate`](Operator::operate) fails.
    pub fn anonymize(
        &self,
        text: &str,
        results: Vec<RecognizerResult>,
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<EngineResult> {
        let start = std::time::Instant::now();
        let outcome = self.anonymize_inner(text, results, operators);

        if self.emit_events {
            record(
                metric_names::anonymize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            match &outcome {
                Ok(result) => {
                    increment_by(metric_names::spans_operated(), result.items.len() as u64);
                    observe::debug(
                        "anonymize",
                        format!("anonymized {} span(s)", result.items.len()),
                    );
                }
                Err(_) => {
                    increment_by(metric_names::errors(), 1);
                }
            }
        }

        outcome
    }

    /// The un-instrumented core of [`anonymize`](AnonymizerEngine::anonymize).
    fn anonymize_inner(
        &self,
        text: &str,
        results: Vec<RecognizerResult>,
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<EngineResult> {
        // Validate every operator config we will use, up front, so an invalid
        // configuration fails before any output is built.
        self.validate_operators(&results, operators)?;

        let resolved = self.resolve_conflicts(results);

        let mut output = String::with_capacity(text.len());
        let mut items: Vec<OperatorResult> = Vec::new();
        let mut cursor: usize = 0;

        for span in &resolved {
            // Skip spans that overlap already-consumed text (possible under the
            // `None` strategy, which performs no overlap resolution).
            if span.start < cursor {
                continue;
            }

            // Copy the verbatim gap before this span.
            let gap = text
                .get(cursor..span.start)
                .ok_or_else(|| span_error(text, cursor, span.start))?;
            output.push_str(gap);

            // Extract the original span text (validates bounds + char boundary).
            let original = text
                .get(span.start..span.end)
                .ok_or_else(|| span_error(text, span.start, span.end))?;

            let config = self.config_for(&span.entity_type, operators);
            let operator = self.lookup(&config.operator_name)?;
            let replacement = operator.operate(original, &span.entity_type, &config)?;

            let out_start = output.len();
            output.push_str(&replacement);
            let out_end = output.len();

            items.push(OperatorResult::new(
                span.entity_type.clone(),
                out_start,
                out_end,
                Some(replacement),
                Some(operator.operator_name().to_string()),
            )?);

            cursor = span.end;
        }

        // Copy the trailing remainder after the last span.
        let tail = text
            .get(cursor..)
            .ok_or_else(|| span_error(text, cursor, text.len()))?;
        output.push_str(tail);

        let mut result = EngineResult::new();
        result.set_text(output);
        for item in items {
            result.add_item(item);
        }
        Ok(result)
    }

    /// Validates the operator config for every distinct entity type in
    /// `results`, ensuring each names a registered operator that accepts it.
    fn validate_operators(
        &self,
        results: &[RecognizerResult],
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<()> {
        for span in results {
            let config = self.config_for(&span.entity_type, operators);
            let operator = self.lookup(&config.operator_name)?;
            operator.validate(&config)?;
        }
        Ok(())
    }

    /// Resolves the per-entity [`OperatorConfig`] for `entity_type`: an explicit
    /// entry, else a `DEFAULT` entry, else a synthesized `replace` config.
    fn config_for(
        &self,
        entity_type: &str,
        operators: &HashMap<String, OperatorConfig>,
    ) -> OperatorConfig {
        if let Some(config) = operators.get(entity_type) {
            return config.clone();
        }
        if let Some(config) = operators.get(DEFAULT_OPERATOR_KEY) {
            return config.clone();
        }
        // `Replace` is always registered, and "replace" is a valid name, so this
        // construction never fails.
        OperatorConfig::new(Replace.operator_name()).unwrap_or_else(|_| OperatorConfig {
            operator_name: Replace.operator_name().to_string(),
            params: HashMap::new(),
        })
    }

    /// Looks up a registered operator by name.
    fn lookup(&self, name: &str) -> Result<&dyn Operator> {
        self.registry
            .get(name)
            .map(AsRef::as_ref)
            .ok_or_else(|| Problem::Validation(format!("unknown anonymize operator: '{name}'")))
    }

    /// Reconciles overlapping detections per the engine's configured strategy,
    /// returning spans sorted by `(start, end)` ready for the rewrite.
    fn resolve_conflicts(&self, results: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
        match self.conflict {
            ConflictResolutionStrategy::None => {
                let mut sorted = results;
                sorted.sort();
                sorted
            }
            ConflictResolutionStrategy::MergeSimilarOrContained => merge_keep_best(results),
            ConflictResolutionStrategy::RemoveIntersections => remove_intersections(results),
        }
    }
}

/// Builds a [`Problem`] describing a span that is out of bounds or not on a
/// char boundary in `text`.
fn span_error(text: &str, start: usize, end: usize) -> Problem {
    Problem::Validation(format!(
        "span [{start}, {end}) is out of bounds or not on a char boundary for text of {} bytes",
        text.len()
    ))
}

/// Orders detections by descending priority: higher score first, then the
/// longer span, then the earlier start. Used to decide which span wins a
/// conflict.
fn priority_cmp(a: &RecognizerResult, b: &RecognizerResult) -> std::cmp::Ordering {
    b.score
        .total_cmp(&a.score)
        .then_with(|| {
            let a_len = a.end.saturating_sub(a.start);
            let b_len = b.end.saturating_sub(b.start);
            b_len.cmp(&a_len)
        })
        .then_with(|| a.start.cmp(&b.start))
}

/// `MergeSimilarOrContained`: greedily keep the highest-priority span and drop
/// any later span that overlaps a kept one. Returns spans sorted by
/// `(start, end)`.
fn merge_keep_best(results: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
    let mut by_priority = results;
    by_priority.sort_by(priority_cmp);

    let mut kept: Vec<RecognizerResult> = Vec::new();
    for candidate in by_priority {
        if kept.iter().any(|k| k.intersects(&candidate)) {
            continue;
        }
        kept.push(candidate);
    }
    kept.sort();
    kept
}

/// `RemoveIntersections`: keep the highest-priority span and trim lower-priority
/// spans to their longest sub-range not covered by an already-kept span,
/// dropping any that are fully covered. Returns spans sorted by `(start, end)`.
fn remove_intersections(results: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
    let mut by_priority = results;
    by_priority.sort_by(priority_cmp);

    let mut kept: Vec<RecognizerResult> = Vec::new();
    for candidate in by_priority {
        // Collect the already-kept ranges that overlap this candidate.
        let mut blockers: Vec<(usize, usize)> = kept
            .iter()
            .filter(|k| k.intersects(&candidate))
            .map(|k| (k.start, k.end))
            .collect();
        blockers.sort_unstable();

        if let Some((start, end)) = longest_free_subrange(candidate.start, candidate.end, &blockers)
        {
            let mut trimmed = candidate.clone();
            trimmed.start = start;
            trimmed.end = end;
            kept.push(trimmed);
        }
    }
    kept.sort();
    kept
}

/// Returns the longest sub-range of `[start, end)` not covered by any of the
/// sorted, `blockers` ranges, or `None` if the whole range is covered.
fn longest_free_subrange(
    start: usize,
    end: usize,
    blockers: &[(usize, usize)],
) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    let mut cursor = start;

    let consider = |from: usize, to: usize, best: &mut Option<(usize, usize)>| {
        if to > from {
            let len = to.saturating_sub(from);
            let is_better = best.is_none_or(|(bs, be)| be.saturating_sub(bs) < len);
            if is_better {
                *best = Some((from, to));
            }
        }
    };

    for &(b_start, b_end) in blockers {
        // Gap between the cursor and the next blocker.
        let gap_end = b_start.min(end);
        consider(cursor, gap_end, &mut best);
        cursor = cursor.max(b_end);
        if cursor >= end {
            break;
        }
    }
    // Trailing gap after the last blocker.
    consider(cursor, end, &mut best);

    best
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn rr(entity: &str, start: usize, end: usize, score: f64) -> RecognizerResult {
        RecognizerResult::new(entity, start, end, score).expect("valid result")
    }

    fn replace_with(value: &str) -> OperatorConfig {
        let mut params = HashMap::new();
        params.insert("new_value".to_string(), json!(value));
        OperatorConfig::with_params("replace", params).expect("valid config")
    }

    #[test]
    fn empty_results_returns_text_unchanged() {
        let engine = AnonymizerEngine::new();
        let out = engine
            .anonymize("nothing to see", Vec::new(), &HashMap::new())
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("nothing to see"));
        assert!(out.items.is_empty());
    }

    #[test]
    fn single_span_default_replace() {
        let engine = AnonymizerEngine::new();
        let out = engine
            .anonymize(
                "SSN 123-45-6789.",
                vec![rr("US_SSN", 4, 15, 0.9)],
                &HashMap::new(),
            )
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("SSN <US_SSN>."));
        assert_eq!(out.items.len(), 1);
        let item = out.items.first().expect("one item");
        // Output offsets point at "<US_SSN>" within the rewritten text.
        assert_eq!(item.start, 4);
        assert_eq!(item.end, 12);
        assert_eq!(item.text.as_deref(), Some("<US_SSN>"));
        assert_eq!(item.operator.as_deref(), Some("replace"));
    }

    #[test]
    fn multi_span_offsets_track_length_change() {
        let engine = AnonymizerEngine::new();
        let mut ops = HashMap::new();
        ops.insert("PERSON".to_string(), replace_with("X")); // shorter than original
        ops.insert(
            "EMAIL_ADDRESS".to_string(),
            replace_with("<<email redacted>>"),
        ); // longer

        // Byte offsets of "Jane <jane@x.io>":
        //  J0 a1 n2 e3 ' '4 <5 j6 a7 n8 e9 @10 x11 .12 i13 o14 >15
        let text = "Jane <jane@x.io>";
        let results = vec![
            rr("PERSON", 0, 4, 0.9),          // "Jane"
            rr("EMAIL_ADDRESS", 6, 15, 0.95), // "jane@x.io"
        ];
        let out = engine.anonymize(text, results, &ops).expect("anonymize");
        // "X" + " <" gap + "<<email redacted>>" + ">" tail.
        assert_eq!(out.text.as_deref(), Some("X <<<email redacted>>>"));

        let first = out.items.first().expect("first");
        assert_eq!((first.start, first.end), (0, 1)); // "X"
        let second = out.items.get(1).expect("second");
        assert_eq!(second.text.as_deref(), Some("<<email redacted>>"));
        // Output: "X" (1) + " <" gap (2) = byte 3 start.
        assert_eq!(second.start, 3);
        assert_eq!(second.end, 21);
    }

    #[test]
    fn redact_zero_width_collapses_text() {
        let engine = AnonymizerEngine::new();
        let mut ops = HashMap::new();
        ops.insert(
            "EMAIL_ADDRESS".to_string(),
            OperatorConfig::new("redact").expect("cfg"),
        );
        let text = "mail me at a@b.co now";
        // "a@b.co" at bytes 11..17
        let out = engine
            .anonymize(text, vec![rr("EMAIL_ADDRESS", 11, 17, 0.9)], &ops)
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("mail me at  now"));
        let item = out.items.first().expect("item");
        assert_eq!(item.start, item.end); // zero-width output
        assert_eq!(item.text.as_deref(), Some(""));
    }

    #[test]
    fn adjacent_spans_both_applied() {
        let engine = AnonymizerEngine::new();
        // "ab" with two touching spans [0,1) and [1,2)
        let out = engine
            .anonymize(
                "ab",
                vec![rr("A", 0, 1, 0.9), rr("B", 1, 2, 0.9)],
                &HashMap::new(),
            )
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("<A><B>"));
        assert_eq!(out.items.len(), 2);
    }

    #[test]
    fn multibyte_offsets_are_byte_accurate() {
        let engine = AnonymizerEngine::new();
        // "héllo NAME" — é is 2 bytes, so "NAME" starts at byte 7.
        let text = "héllo Bob";
        //  h0 é1..3 l3 l4 o5 ' '6 B7 o8 b9
        let out = engine
            .anonymize(text, vec![rr("PERSON", 7, 10, 0.9)], &HashMap::new())
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("héllo <PERSON>"));
    }

    #[test]
    fn unknown_operator_errors() {
        let engine = AnonymizerEngine::new();
        let mut ops = HashMap::new();
        ops.insert(
            "PERSON".to_string(),
            OperatorConfig::new("nonexistent").expect("cfg"),
        );
        let err = engine.anonymize("Bob", vec![rr("PERSON", 0, 3, 0.9)], &ops);
        assert!(err.is_err());
    }

    #[test]
    fn out_of_bounds_span_errors() {
        let engine = AnonymizerEngine::new();
        let err = engine.anonymize("short", vec![rr("X", 2, 99, 0.9)], &HashMap::new());
        assert!(err.is_err());
    }

    #[test]
    fn non_char_boundary_span_errors() {
        let engine = AnonymizerEngine::new();
        // "é" is two bytes; a span ending at byte 1 splits the char.
        let err = engine.anonymize("é", vec![rr("X", 0, 1, 0.9)], &HashMap::new());
        assert!(err.is_err());
    }

    #[test]
    fn default_key_used_for_unmapped_entity() {
        let engine = AnonymizerEngine::new();
        let mut ops = HashMap::new();
        ops.insert(
            "DEFAULT".to_string(),
            OperatorConfig::new("redact").expect("cfg"),
        );
        let out = engine
            .anonymize("x Bob y", vec![rr("PERSON", 2, 5, 0.9)], &ops)
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("x  y"));
    }

    #[test]
    fn merge_keeps_highest_score_on_overlap() {
        let engine = AnonymizerEngine::new(); // default = MergeSimilarOrContained
        // Two overlapping spans; the higher-scoring PERSON should win.
        let results = vec![rr("ORG", 0, 8, 0.5), rr("PERSON", 0, 8, 0.9)];
        let out = engine
            .anonymize("Big Name", results, &HashMap::new())
            .expect("anon");
        assert_eq!(out.text.as_deref(), Some("<PERSON>"));
        assert_eq!(out.items.len(), 1);
    }

    #[test]
    fn none_strategy_skips_overlap_first_by_position() {
        let engine =
            AnonymizerEngine::new().with_conflict_strategy(ConflictResolutionStrategy::None);
        // Overlapping spans; None does no resolution, rewrite takes the first by
        // (start,end) and skips the overlapping one.
        let results = vec![rr("A", 0, 5, 0.9), rr("B", 2, 8, 0.95)];
        let out = engine
            .anonymize("abcdefgh", results, &HashMap::new())
            .expect("anon");
        // First span [0,5) → <A>, second [2,8) overlaps → skipped; tail "fgh".
        assert_eq!(out.text.as_deref(), Some("<A>fgh"));
        assert_eq!(out.items.len(), 1);
    }

    #[test]
    fn remove_intersections_trims_lower_priority() {
        let engine = AnonymizerEngine::new()
            .with_conflict_strategy(ConflictResolutionStrategy::RemoveIntersections);
        // High-priority [2,5) wins; low-priority [0,4) trims to [0,2).
        let results = vec![rr("LOW", 0, 4, 0.5), rr("HIGH", 2, 5, 0.9)];
        let out = engine
            .anonymize("abcdef", results, &HashMap::new())
            .expect("anon");
        //  [0,2)="ab" → <LOW>, [2,5)="cde" → <HIGH>, tail "f"
        assert_eq!(out.text.as_deref(), Some("<LOW><HIGH>f"));
        assert_eq!(out.items.len(), 2);
    }

    #[test]
    fn longest_free_subrange_picks_biggest_gap() {
        // range [0,10), blockers cover [2,4) and [5,6): gaps [0,2),[4,5),[6,10).
        let got = longest_free_subrange(0, 10, &[(2, 4), (5, 6)]);
        assert_eq!(got, Some((6, 10)));
    }

    #[test]
    fn longest_free_subrange_none_when_fully_covered() {
        assert_eq!(longest_free_subrange(2, 5, &[(0, 10)]), None);
    }

    #[test]
    fn mask_operator_tail_masks_through_engine() {
        // The built-in `mask` operator is reachable by name and tail-masks a
        // PAN span, preserving the surrounding text and the leading digits.
        let engine = AnonymizerEngine::new();
        let mut params = HashMap::new();
        params.insert("masking_char".to_string(), json!("*"));
        params.insert("chars_to_mask".to_string(), json!(12));
        params.insert("from_end".to_string(), json!(true));
        let mut ops = HashMap::new();
        ops.insert(
            "CREDIT_CARD".to_string(),
            OperatorConfig::with_params("mask", params).expect("cfg"),
        );

        // "card 4111-1111-1111-1234." — PAN spans bytes 5..24.
        let text = "card 4111-1111-1111-1234.";
        let out = engine
            .anonymize(text, vec![rr("CREDIT_CARD", 5, 24, 0.99)], &ops)
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("card 4111-11************."));
        let item = out.items.first().expect("one item");
        assert_eq!(item.operator.as_deref(), Some("mask"));
    }

    #[test]
    fn mask_operator_invalid_config_fails_engine_up_front() {
        // A negative chars_to_mask must fail validation before any output is
        // built (not silently no-op, the Presidio anti-pattern).
        let engine = AnonymizerEngine::new();
        let mut params = HashMap::new();
        params.insert("masking_char".to_string(), json!("*"));
        params.insert("chars_to_mask".to_string(), json!(-1));
        let mut ops = HashMap::new();
        ops.insert(
            "US_SSN".to_string(),
            OperatorConfig::with_params("mask", params).expect("cfg"),
        );
        let err = engine.anonymize("123-45-6789", vec![rr("US_SSN", 0, 11, 0.9)], &ops);
        assert!(err.is_err());
    }

    #[test]
    fn silent_engine_still_transforms() {
        let engine = AnonymizerEngine::new().silent();
        let out = engine
            .anonymize("Bob", vec![rr("PERSON", 0, 3, 0.9)], &HashMap::new())
            .expect("anon");
        assert_eq!(out.text.as_deref(), Some("<PERSON>"));
    }
}
