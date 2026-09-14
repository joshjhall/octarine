//! The analysis pipeline, one function per pass.
//!
//! [`AnalyzerEngine`](crate::analyze::AnalyzerEngine) is a thin shell over the
//! functions here. Splitting the passes out is deliberate: each is
//! independently testable against a hand-built result set, and each is the
//! named attachment point for a feature that extends it. A single opaque
//! `analyze()` body would make both impossible.
//!
//! # Pass order
//!
//! The order mirrors Presidio's `AnalyzerEngine.analyze`, because the order is
//! load-bearing rather than incidental:
//!
//! | # | Pass | Notes |
//! |---|------|-------|
//! | 1 | [`resolve_recognizers`] | language + entity set → recognizer list |
//! | 2 | *NLP artifacts* | **not implemented** — see below |
//! | 3 | [`run_recognizers`] | await each, aggregate |
//! | 4 | [`inject_metadata`] | stamp recognizer provenance |
//! | 5 | [`enhance_context`] | raise scores on nearby context keywords |
//! | 6 | *allow-list* | **not implemented** — see below |
//! | 7 | [`deduplicate`] | reconcile overlapping spans |
//! | 8 | [`apply_threshold`] | drop low-scoring results |
//! | 9 | [`finalize`] | strip explanations unless requested |
//!
//! Enhancement (5) must precede thresholding (8), or a result the context
//! would have rescued is discarded before the rescue runs. Dedup (7) must
//! precede thresholding for the same reason in reverse: a span absorbed by a
//! longer one should not influence the surviving set's scores.
//!
//! # Unimplemented passes
//!
//! Steps 2 and 6 are **documented seams, not stubs**. Step 2 (NLP
//! `process_text` producing tokens and lemmas) requires an NER model; step 6
//! (allow-list filtering) is a feature with its own semantics to settle. Each
//! lands with the pass that reads it — a knob that parses but reaches no
//! consumer is a silent no-op, and the only way a caller finds out is wrong
//! output in production.

use std::sync::Arc;

use serde_json::Value;

use crate::analyze::{AnalysisExplanation, ConflictResolution, Recognizer, RecognizerRegistry};
use crate::anonymize::RecognizerResult;
use crate::observe;
use crate::primitives::identifiers::confidence::{
    ConfidenceBuilder as PrimitiveConfidenceBuilder, ContextConfig,
};
use crate::primitives::identifiers::types::IdentifierType;

/// Metadata key carrying the name of the recognizer that produced a result.
pub(crate) const RECOGNIZER_NAME_KEY: &str = "recognizer_name";

/// Metadata key marking a result whose score already reflects context.
///
/// Mirrors Presidio's `IS_SCORE_ENHANCED_BY_CONTEXT_KEY`, and exists for the
/// same reason: a recognizer may do its own context scoring, and the engine's
/// enhancement pass must not then count the same evidence a second time.
/// [`enhance_context`] skips any result carrying this key.
///
/// **Not a security boundary.** Any registered recognizer can set this key,
/// and is trusted to set it honestly — but a recognizer is in-process code the
/// host chose to register, and one that wanted to depress its own scores could
/// simply return lower ones. The marker adds no authority a recognizer did not
/// already have.
pub(crate) const CONTEXT_ENHANCED_KEY: &str = "is_score_enhanced_by_context";

/// Step 1 — selects the recognizers worth calling for `entities`.
///
/// Delegates to [`RecognizerRegistry::recognizers_for`], which honors the
/// empty-means-everything convention on both sides.
#[must_use]
pub(crate) fn resolve_recognizers(
    registry: &RecognizerRegistry,
    entities: &[IdentifierType],
) -> Vec<Arc<dyn Recognizer>> {
    registry.recognizers_for(entities)
}

/// Step 3 — runs every recognizer and aggregates their results.
///
/// # Failure handling
///
/// A recognizer returning `Err` is logged and **skipped**; the run continues
/// with the others. One narrow recognizer — an unreachable remote service, a
/// rate-limited LLM — must not fail an analysis the other recognizers could
/// have answered. The returned count of failures lets the caller record a
/// metric, so a degraded run is visible rather than silently thinner.
///
/// This is the one place the "empty is not an error" rule from
/// [`Recognizer::analyze`] is enforced at the pipeline level: a recognizer
/// that found nothing contributes nothing, and is indistinguishable from one
/// that was not called — which is correct. A recognizer that *could not look*
/// is counted as a failure instead.
///
/// `emit_events` gates the failure log. A *custom* recognizer's failure is
/// logged here rather than inside the recognizer, so this is the only point
/// that can honor a silent engine for it — the failure is still **counted**
/// either way, because silencing observability must not silence the metric a
/// caller uses to notice a degraded run.
pub(crate) async fn run_recognizers(
    recognizers: &[Arc<dyn Recognizer>],
    text: &str,
    language: &str,
    entities: &[IdentifierType],
    emit_events: bool,
) -> (Vec<RecognizerResult>, usize) {
    let mut aggregated = Vec::new();
    let mut failures = 0usize;

    for recognizer in recognizers {
        match recognizer.analyze(text, language, entities).await {
            Ok(mut results) => {
                inject_metadata(&mut results, recognizer.name());
                aggregated.append(&mut results);
            }
            Err(problem) => {
                failures = failures.saturating_add(1);
                if emit_events {
                    // The recognizer name is safe to log; the analyzed text is not.
                    observe::warn(
                        "analyze_recognizer_failed",
                        format!(
                            "Recognizer '{}' failed; continuing without it: {problem}",
                            recognizer.name()
                        ),
                    );
                }
            }
        }
    }

    (aggregated, failures)
}

/// Step 4 — stamps recognizer provenance onto every result.
///
/// Called by [`run_recognizers`], which is the only point that still knows
/// which recognizer produced which result. Keys the recognizer set itself are
/// preserved: a recognizer may record its own detail, and the pipeline adds to
/// that rather than replacing it.
pub(crate) fn inject_metadata(results: &mut [RecognizerResult], recognizer_name: &str) {
    for result in results {
        let metadata = result
            .recognition_metadata
            .get_or_insert_with(Default::default);
        metadata.insert(
            RECOGNIZER_NAME_KEY.to_string(),
            Value::String(recognizer_name.to_string()),
        );
    }
}

/// How much a supportive keyword adds, and the ceiling it may reach.
///
/// Read from [`ContextConfig::default()`] rather than restated as literals, so
/// this pass tracks the primitive's tuning instead of a stale copy of it.
///
/// # This is not parity with the built-in path
///
/// The two scoring paths share the *context-detection* settings — window size
/// and language — but not the arithmetic, and a retune of these two numbers
/// moves only this one:
///
/// | Path | How context changes the score |
/// | ---- | ----------------------------- |
/// | `scan_text` (built-in) | a **discrete enum step** — `with_context_boost` promotes `Low → Medium → High`, which `score_for` then maps to fixed constants |
/// | this pass (custom recognizers) | an **additive** `+boost`, clamped to `ceiling` |
///
/// Unifying them means deriving `score_for`'s constants — or the enum
/// transition itself — from the same config, which is a change to the
/// identifier primitives rather than to this module.
fn context_boost_and_ceiling() -> (f64, f64) {
    let config = ContextConfig::default();
    (config.boost_factor, config.max_confidence)
}

/// Step 5 — raises scores for results with a supportive keyword nearby.
///
/// # Division of labor
///
/// Keyword detection is **not** reimplemented here. Deciding whether a
/// supportive word sits near a span — the window math, the multilingual
/// keyword tables, the case folding — lives in
/// [`crate::primitives::identifiers::confidence`], and this pass asks it via
/// [`is_context_present`](crate::primitives::identifiers::confidence::ConfidenceBuilder::is_context_present).
///
/// The *scoring* is applied here rather than delegated, because the
/// primitive's scorer returns an **absolute** score built from its own fixed
/// base rather than a boost relative to an input. Feeding it a result that
/// already scored 0.85 from a passing checksum would return a lower number and
/// silently downgrade a validated detection. So: the primitive answers "is
/// there context?", and this pass answers "what does that do to *this*
/// result's score?" — an additive boost, capped.
///
/// `language` is forwarded as a keyword-language hint. An unrecognized tag
/// leaves the analyzer unhinted — scanning every language's keyword table —
/// rather than matching nothing, so a typo'd tag degrades to the default
/// instead of silently suppressing every boost.
///
/// A result whose entity type does not map back to a known
/// [`IdentifierType`] is passed through untouched: a custom recognizer's
/// bespoke label has no keyword table to consult, which is an absence of
/// context, not a reason to drop the detection.
pub(crate) fn enhance_context(
    results: &mut [RecognizerResult],
    text: &str,
    language: &str,
) -> usize {
    let scorer = PrimitiveConfidenceBuilder::new().with_language_hint(language);
    let (boost, ceiling) = context_boost_and_ceiling();
    let mut boosted = 0usize;

    for result in results.iter_mut() {
        // A recognizer that already scored its own context must not have that
        // evidence counted a second time here.
        if is_context_enhanced(result) {
            continue;
        }
        let Ok(entity) = result.entity_type.parse::<IdentifierType>() else {
            continue;
        };
        if !scorer.is_context_present(text, result.start, result.end, &entity) {
            continue;
        }

        let original = result.score;
        let enhanced = (original + boost).min(ceiling);
        if enhanced <= original {
            // Already at or above the cap — the context tells us nothing new.
            continue;
        }

        result.score = enhanced;
        boosted = boosted.saturating_add(1);

        let recognizer = result
            .recognition_metadata
            .as_ref()
            .and_then(|m| m.get(RECOGNIZER_NAME_KEY))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        // The supportive word itself is not surfaced: the primitive reports
        // presence, not which keyword matched, and inventing one would make
        // the trace lie.
        result.analysis_explanation = Some(
            AnalysisExplanation::new(recognizer, original)
                .with_context_boost("(context)", enhanced)
                .to_string(),
        );
    }

    boosted
}

/// Whether `result` carries the [`CONTEXT_ENHANCED_KEY`] marker.
fn is_context_enhanced(result: &RecognizerResult) -> bool {
    result
        .recognition_metadata
        .as_ref()
        .and_then(|m| m.get(CONTEXT_ENHANCED_KEY))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Marks `result` as already context-enhanced, so [`enhance_context`] skips it.
///
/// A recognizer that does its own context scoring calls this; without it the
/// engine adds its own boost on top and the same keyword raises the score
/// twice.
pub(crate) fn mark_context_enhanced(result: &mut RecognizerResult) {
    let metadata = result
        .recognition_metadata
        .get_or_insert_with(Default::default);
    metadata.insert(CONTEXT_ENHANCED_KEY.to_string(), Value::Bool(true));
}

/// Step 7 — reconciles overlapping spans.
#[must_use]
pub(crate) fn deduplicate(
    results: Vec<RecognizerResult>,
    text: &str,
    strategy: ConflictResolution,
) -> Vec<RecognizerResult> {
    strategy.resolve_results(text, results)
}

/// Step 8 — drops results scoring below `threshold`.
///
/// The comparison is `score < threshold`, so a threshold equal to a result's
/// score keeps it. `threshold` is clamped to `[0.0, 1.0]`, and a non-finite
/// threshold is treated as no threshold at all: a caller's bad number degrades
/// to "keep everything" rather than silently discarding every detection, which
/// for a PII detector is the safer direction to fail.
#[must_use]
pub(crate) fn apply_threshold(
    results: Vec<RecognizerResult>,
    threshold: f64,
) -> Vec<RecognizerResult> {
    if !threshold.is_finite() {
        return results;
    }
    let threshold = threshold.clamp(0.0, 1.0);
    results
        .into_iter()
        .filter(|r| r.score >= threshold)
        .collect()
}

/// Step 9 — strips explanations unless the caller asked to keep them.
///
/// Explanations are built during enhancement regardless, because the pass that
/// can explain a score is the pass that changed it. Withholding them from the
/// response is a separate decision from whether to compute them.
#[must_use]
pub(crate) fn finalize(
    mut results: Vec<RecognizerResult>,
    return_decision_process: bool,
) -> Vec<RecognizerResult> {
    if !return_decision_process {
        for result in &mut results {
            result.analysis_explanation = None;
        }
    }
    results
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    use async_trait::async_trait;

    use crate::observe::{Problem, Result};

    fn rr(entity_type: &str, start: usize, end: usize, score: f64) -> RecognizerResult {
        RecognizerResult::new(entity_type, start, end, score).expect("valid test result")
    }

    /// Returns one fixed result.
    struct FixedRecognizer {
        label: &'static str,
        entity: &'static str,
    }

    #[async_trait]
    impl Recognizer for FixedRecognizer {
        async fn analyze(
            &self,
            _text: &str,
            _language: &str,
            _entities: &[IdentifierType],
        ) -> Result<Vec<RecognizerResult>> {
            Ok(vec![rr(self.entity, 0, 4, 0.9)])
        }

        fn name(&self) -> &str {
            self.label
        }

        fn supported_entities(&self) -> &[IdentifierType] {
            &[]
        }
    }

    /// Always fails — stands in for an unreachable remote service.
    struct FailingRecognizer;

    #[async_trait]
    impl Recognizer for FailingRecognizer {
        async fn analyze(
            &self,
            _text: &str,
            _language: &str,
            _entities: &[IdentifierType],
        ) -> Result<Vec<RecognizerResult>> {
            Err(Problem::Network("upstream unavailable".to_string()))
        }

        fn name(&self) -> &str {
            "failing"
        }

        fn supported_entities(&self) -> &[IdentifierType] {
            &[]
        }
    }

    #[tokio::test]
    async fn a_failing_recognizer_does_not_sink_the_run() {
        let recognizers: Vec<Arc<dyn Recognizer>> = vec![
            Arc::new(FailingRecognizer),
            Arc::new(FixedRecognizer {
                label: "fixed",
                entity: "US_SSN",
            }),
        ];

        let (results, failures) = run_recognizers(&recognizers, "text", "en", &[], false).await;

        assert_eq!(failures, 1, "the failure must be counted, not swallowed");
        assert_eq!(
            results.len(),
            1,
            "the healthy recognizer's results must still come back"
        );
        assert_eq!(
            results.first().map(|r| r.entity_type.as_str()),
            Some("US_SSN")
        );
    }

    #[tokio::test]
    async fn a_failure_is_counted_even_when_events_are_silenced() {
        // Silencing observability must not silence the metric a caller uses to
        // notice a degraded run: the log is gated, the count is not.
        let recognizers: Vec<Arc<dyn Recognizer>> = vec![Arc::new(FailingRecognizer)];

        let (results, silent_failures) =
            run_recognizers(&recognizers, "text", "en", &[], false).await;
        let (_, loud_failures) = run_recognizers(&recognizers, "text", "en", &[], true).await;

        assert!(results.is_empty());
        assert_eq!(
            silent_failures, 1,
            "a silenced failure must still be counted"
        );
        assert_eq!(
            silent_failures, loud_failures,
            "the emit_events flag must change logging only, never the tally"
        );
    }

    #[tokio::test]
    async fn results_are_stamped_with_their_producing_recognizer() {
        let recognizers: Vec<Arc<dyn Recognizer>> = vec![Arc::new(FixedRecognizer {
            label: "alpha",
            entity: "US_SSN",
        })];

        let (results, _) = run_recognizers(&recognizers, "text", "en", &[], false).await;
        let name = results
            .first()
            .and_then(|r| r.recognition_metadata.as_ref())
            .and_then(|m| m.get(RECOGNIZER_NAME_KEY))
            .and_then(Value::as_str);
        assert_eq!(name, Some("alpha"));
    }

    #[test]
    fn inject_metadata_preserves_recognizer_supplied_keys() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("custom".to_string(), Value::String("kept".to_string()));
        let mut results = vec![rr("US_SSN", 0, 4, 0.9).with_metadata(metadata)];

        inject_metadata(&mut results, "alpha");

        let m = results
            .first()
            .and_then(|r| r.recognition_metadata.as_ref())
            .expect("metadata present");
        assert_eq!(m.get("custom").and_then(Value::as_str), Some("kept"));
        assert_eq!(
            m.get(RECOGNIZER_NAME_KEY).and_then(Value::as_str),
            Some("alpha")
        );
    }

    #[test]
    fn threshold_drops_below_and_keeps_at_the_boundary() {
        let results = vec![
            rr("US_SSN", 0, 4, 0.3),
            rr("US_SSN", 5, 9, 0.5),
            rr("US_SSN", 10, 14, 0.9),
        ];

        let kept = apply_threshold(results, 0.5);
        let scores: Vec<f64> = kept.iter().map(|r| r.score).collect();
        assert_eq!(
            scores,
            vec![0.5, 0.9],
            "the below-threshold result must go and the boundary result must stay"
        );
    }

    #[test]
    fn threshold_above_one_is_clamped_to_one() {
        // Clamped to 1.0, so anything below a perfect score is dropped...
        assert!(
            apply_threshold(vec![rr("US_SSN", 0, 4, 0.99)], 1.5).is_empty(),
            "a threshold above the score range clamps to 1.0, not to infinity"
        );
        // ...while a perfect score still meets it, since the test is `>=`.
        assert_eq!(
            apply_threshold(vec![rr("US_SSN", 0, 4, 1.0)], 1.5).len(),
            1,
            "clamping must not turn into an unsatisfiable threshold"
        );
    }

    // No test for a negative threshold: scores are always >= 0.0, so
    // `score >= -1.0` and `score >= 0.0` accept exactly the same set. No input
    // can distinguish clamped from unclamped on that side, and a test that
    // cannot fail is worse than no test — it reports coverage it does not have.

    #[test]
    fn non_finite_threshold_keeps_everything() {
        let results = vec![rr("US_SSN", 0, 4, 0.1)];
        assert_eq!(
            apply_threshold(results, f64::NAN).len(),
            1,
            "a bad threshold must fail toward keeping detections, not discarding them"
        );
    }

    #[test]
    fn finalize_strips_explanations_unless_requested() {
        let explained = vec![rr("US_SSN", 0, 4, 0.9).with_explanation("because")];

        let stripped = finalize(explained.clone(), false);
        assert!(
            stripped.first().map(|r| r.analysis_explanation.is_none()) == Some(true),
            "explanations must not leak into a response that did not ask for them"
        );

        let kept = finalize(explained, true);
        assert_eq!(
            kept.first().and_then(|r| r.analysis_explanation.as_deref()),
            Some("because")
        );
    }

    #[test]
    fn enhance_context_boosts_and_explains_a_keyword_adjacent_match() {
        let text = "SSN: 123-45-6789";
        let start = 5;
        let end = text.len();
        let mut results = vec![rr("US_SSN", start, end, 0.5)];
        inject_metadata(&mut results, "identifiers");

        let boosted = enhance_context(&mut results, text, "en");

        assert_eq!(boosted, 1, "the 'SSN:' prefix is a supportive context word");
        let result = results.first().expect("one result");
        assert!(
            result.score > 0.5,
            "context should raise the score, got {}",
            result.score
        );
        let explanation = result
            .analysis_explanation
            .as_deref()
            .expect("a boosted result must explain itself");
        assert!(
            explanation.contains("identifiers"),
            "the explanation must name the recognizer, got {explanation}"
        );
    }

    #[test]
    fn boost_and_ceiling_are_returned_in_that_order() {
        // The sibling tests read their expected values from this function, so
        // a swapped tuple would move production and expectation together and
        // go unnoticed. Pin the numbers once, here, independently.
        let (boost, ceiling) = context_boost_and_ceiling();
        assert!(
            (boost - 0.35).abs() < f64::EPSILON,
            "expected Presidio's 0.35 similarity factor, got {boost}"
        );
        assert!(
            (ceiling - 0.95).abs() < f64::EPSILON,
            "expected the 0.95 cap, got {ceiling}"
        );
        assert!(boost < ceiling, "a boost larger than the cap is nonsense");
    }

    #[test]
    fn enhance_context_caps_the_boost_at_the_ceiling() {
        // A validated identifier (0.85) plus the context boost exceeds both the
        // ceiling and RecognizerResult's valid range — a reachable combination,
        // not a hypothetical one.
        let (_, ceiling) = context_boost_and_ceiling();
        let text = "SSN: 412-77-3856";
        let mut results = vec![rr("US_SSN", 5, text.len(), 0.85)];
        inject_metadata(&mut results, "identifiers");

        let boosted = enhance_context(&mut results, text, "en");

        assert_eq!(boosted, 1);
        assert_eq!(
            results.first().map(|r| r.score),
            Some(ceiling),
            "the boost must clamp to the ceiling, not exceed the valid score range"
        );
    }

    #[test]
    fn enhance_context_skips_a_result_already_at_the_ceiling() {
        let (_, ceiling) = context_boost_and_ceiling();
        let text = "SSN: 412-77-3856";
        let mut results = vec![rr("US_SSN", 5, text.len(), ceiling)];
        inject_metadata(&mut results, "identifiers");

        let boosted = enhance_context(&mut results, text, "en");

        assert_eq!(boosted, 0, "a saturated score cannot be raised further");
        assert!(
            results.first().map(|r| r.analysis_explanation.is_none()) == Some(true),
            "no boost happened, so nothing may claim one in the trace"
        );
    }

    #[test]
    fn enhance_context_skips_a_result_already_enhanced_by_its_recognizer() {
        // The regression: scan_text folds context into confidence before the
        // adapter scores it, so boosting again here counts one keyword twice.
        let text = "SSN: 412-77-3856";
        let mut results = vec![rr("US_SSN", 5, text.len(), 0.6)];
        inject_metadata(&mut results, "identifiers");
        if let Some(result) = results.first_mut() {
            mark_context_enhanced(result);
        }

        let boosted = enhance_context(&mut results, text, "en");

        assert_eq!(
            boosted, 0,
            "an already-enhanced result must not be re-boosted"
        );
        assert_eq!(
            results.first().map(|r| r.score),
            Some(0.6),
            "the score must be left exactly as the recognizer set it"
        );
        assert!(
            results.first().map(|r| r.analysis_explanation.is_none()) == Some(true),
            "the skip happens before any explanation is written; nothing may claim a boost"
        );
    }

    #[test]
    fn enhance_context_attributes_an_unstamped_result_to_unknown() {
        // No inject_metadata: the explanation has no recognizer to name.
        let text = "SSN: 412-77-3856";
        let mut results = vec![rr("US_SSN", 5, text.len(), 0.5)];

        assert_eq!(enhance_context(&mut results, text, "en"), 1);
        let explanation = results
            .first()
            .and_then(|r| r.analysis_explanation.as_deref())
            .expect("a boosted result explains itself");
        assert!(
            explanation.starts_with("unknown:"),
            "an unstamped result must be attributed to 'unknown', got {explanation}"
        );
    }

    #[test]
    fn enhance_context_still_boosts_under_an_unrecognized_language_tag() {
        // The documented degrade: a typo'd tag leaves the scorer unhinted
        // rather than matching nothing.
        let text = "SSN: 412-77-3856";
        let mut results = vec![rr("US_SSN", 5, text.len(), 0.5)];
        inject_metadata(&mut results, "identifiers");

        assert_eq!(
            enhance_context(&mut results, text, "xx-ZZ"),
            1,
            "an unrecognized tag must degrade to scanning every keyword table, \
             not to suppressing every boost"
        );
    }

    #[test]
    fn enhance_context_leaves_unknown_entity_labels_alone() {
        let text = "SSN: 123-45-6789";
        let mut results = vec![rr("CUSTOMER_LOYALTY_ID", 5, text.len(), 0.5)];

        let boosted = enhance_context(&mut results, text, "en");

        assert_eq!(boosted, 0);
        assert_eq!(
            results.first().map(|r| r.score),
            Some(0.5),
            "a custom label has no keyword table; it must pass through untouched, not be dropped"
        );
    }

    #[test]
    fn deduplicate_delegates_to_the_configured_strategy() {
        let text = "user@example.com";
        let results = vec![
            rr("EMAIL_ADDRESS", 0, 16, 0.8),
            rr("EMAIL_ADDRESS", 5, 12, 0.9),
        ];

        let out = deduplicate(results, text, ConflictResolution::SameTypeContainment);
        assert_eq!(out.len(), 1);
        assert_eq!(out.first().map(|r| (r.start, r.end)), Some((0, 16)));
    }
}
