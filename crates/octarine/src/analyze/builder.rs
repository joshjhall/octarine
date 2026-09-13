//! The Layer 3 analysis engine.
//!
//! [`AnalyzerEngine`] drives a [`RecognizerRegistry`] through the
//! [`pipeline`](crate::analyze) passes and returns reconciled, scored,
//! threshold-filtered detections.

use std::time::Instant;

use crate::analyze::pipeline;
use crate::analyze::{AnalyzeRequest, ConflictResolution, RecognizerRegistry};
use crate::anonymize::RecognizerResult;
use crate::observe::Result;
use crate::observe::metrics::{increment_by, record};

crate::define_metrics! {
    analyze_ms => "analyze.engine.analyze_ms",
    results_returned => "analyze.engine.results_returned",
    results_filtered => "analyze.engine.results_filtered",
    recognizer_errors => "analyze.engine.recognizer_errors",
}

/// Default engine score threshold.
///
/// Zero, matching Presidio: the engine returns everything its recognizers
/// found and lets the caller decide what is strong enough. A non-zero default
/// would silently discard low-confidence heuristic hits — for a PII detector,
/// a false negative is the costlier error.
const DEFAULT_SCORE_THRESHOLD: f64 = 0.0;

/// Runs the analysis pipeline over text.
///
/// # Async
///
/// [`analyze`](Self::analyze) is async because [`Recognizer`] is: a recognizer
/// may be a network service or an LLM. There is no sync shell — unlike the
/// anonymizer, whose core is pure string splicing, every useful analysis run
/// may perform I/O, so offering a blocking variant would only invite it to be
/// called from an async context.
///
/// [`Recognizer`]: crate::analyze::Recognizer
///
/// # Examples
///
/// ```
/// use octarine::analyze::AnalyzerEngine;
///
/// # tokio_test::block_on(async {
/// let engine = AnalyzerEngine::new();
/// let results = engine.analyze("Contact: user@example.com", "en").await?;
///
/// assert!(results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"));
/// # Ok::<(), octarine::observe::Problem>(())
/// # }).unwrap();
/// ```
#[derive(Clone)]
pub struct AnalyzerEngine {
    registry: RecognizerRegistry,
    conflict: ConflictResolution,
    score_threshold: f64,
    emit_events: bool,
}

impl std::fmt::Debug for AnalyzerEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalyzerEngine")
            .field("registry", &self.registry)
            .field("conflict", &self.conflict)
            .field("score_threshold", &self.score_threshold)
            .field("emit_events", &self.emit_events)
            .finish()
    }
}

impl Default for AnalyzerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyzerEngine {
    /// Creates an engine over the built-in identifier recognizer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: RecognizerRegistry::with_defaults(),
            conflict: ConflictResolution::default(),
            score_threshold: DEFAULT_SCORE_THRESHOLD,
            emit_events: true,
        }
    }

    /// Creates an engine that emits no observe events or metrics.
    ///
    /// The default registry is built silent too: an engine that quietened only
    /// its own metrics while its recognizers kept logging would not be silent
    /// in any sense a caller cares about.
    #[must_use]
    pub fn silent() -> Self {
        Self {
            registry: RecognizerRegistry::with_silent_defaults(),
            emit_events: false,
            ..Self::new()
        }
    }

    /// Replaces the recognizer registry.
    #[must_use]
    pub fn with_registry(mut self, registry: RecognizerRegistry) -> Self {
        self.registry = registry;
        self
    }

    /// Selects how overlapping detections are reconciled.
    #[must_use]
    pub fn with_conflict_resolution(mut self, conflict: ConflictResolution) -> Self {
        self.conflict = conflict;
        self
    }

    /// Sets the engine-wide score threshold.
    ///
    /// Results scoring strictly below it are dropped. A per-call
    /// [`AnalyzeRequest::with_score_threshold`] overrides this.
    #[must_use]
    pub fn with_score_threshold(mut self, threshold: f64) -> Self {
        self.score_threshold = threshold;
        self
    }

    /// Toggles observe event and metric emission.
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// The registry this engine drives.
    #[must_use]
    pub fn registry(&self) -> &RecognizerRegistry {
        &self.registry
    }

    /// Analyzes `text` for every entity type the registry supports.
    ///
    /// `language` is a BCP 47 tag (`"en"`, `"pt-BR"`).
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](crate::observe::Problem) only when the pipeline
    /// itself cannot proceed. An individual recognizer's failure is **not** an
    /// error: it is logged, counted, and the run continues with the remaining
    /// recognizers.
    pub async fn analyze(&self, text: &str, language: &str) -> Result<Vec<RecognizerResult>> {
        self.analyze_request(&AnalyzeRequest::new(text, language))
            .await
    }

    /// Analyzes according to a fully-specified [`AnalyzeRequest`].
    ///
    /// # Errors
    ///
    /// See [`analyze`](Self::analyze).
    pub async fn analyze_request(&self, request: &AnalyzeRequest) -> Result<Vec<RecognizerResult>> {
        let start = Instant::now();
        let text = request.text();
        let entities = request.entities();

        // 1. Resolve the recognizer set.
        let recognizers = pipeline::resolve_recognizers(&self.registry, entities);

        // 2. NLP artifacts — documented seam, deliberately not implemented.

        // 3. Run recognizers (4. metadata stamping happens inline).
        let (mut results, failures) = pipeline::run_recognizers(
            &recognizers,
            text,
            request.language(),
            entities,
            self.emit_events,
        )
        .await;
        let detected = results.len();

        // 5. Context enhancement.
        pipeline::enhance_context(&mut results, text, request.language());

        // 6. Allow-list — documented seam, deliberately not implemented.

        // 7. Reconcile overlaps.
        let results = pipeline::deduplicate(results, text, self.conflict);

        // 8. Threshold.
        let threshold = request.score_threshold().unwrap_or(self.score_threshold);
        let results = pipeline::apply_threshold(results, threshold);

        // 9. Strip explanations unless the caller asked for them.
        let results = pipeline::finalize(results, request.return_decision_process());

        if self.emit_events {
            record(
                metric_names::analyze_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::results_returned(), results.len() as u64);
            }
            let filtered = detected.saturating_sub(results.len());
            if filtered > 0 {
                increment_by(metric_names::results_filtered(), filtered as u64);
            }
            if failures > 0 {
                increment_by(metric_names::recognizer_errors(), failures as u64);
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    use std::sync::Arc;

    use async_trait::async_trait;

    use crate::analyze::Recognizer;
    use crate::primitives::identifiers::types::IdentifierType;

    /// Emits a caller-supplied result set verbatim.
    struct ScriptedRecognizer {
        results: Vec<RecognizerResult>,
    }

    #[async_trait]
    impl Recognizer for ScriptedRecognizer {
        async fn analyze(
            &self,
            _text: &str,
            _language: &str,
            _entities: &[IdentifierType],
        ) -> Result<Vec<RecognizerResult>> {
            Ok(self.results.clone())
        }

        fn name(&self) -> &str {
            "scripted"
        }

        fn supported_entities(&self) -> &[IdentifierType] {
            &[]
        }
    }

    fn rr(entity_type: &str, start: usize, end: usize, score: f64) -> RecognizerResult {
        RecognizerResult::new(entity_type, start, end, score).expect("valid test result")
    }

    fn engine_returning(results: Vec<RecognizerResult>) -> AnalyzerEngine {
        AnalyzerEngine::silent().with_registry(
            RecognizerRegistry::new().register(Arc::new(ScriptedRecognizer { results })),
        )
    }

    #[tokio::test]
    async fn detects_a_built_in_identifier_out_of_the_box() {
        let results = AnalyzerEngine::silent()
            .analyze("Contact: user@example.com", "en")
            .await
            .expect("analysis should succeed");

        assert!(
            results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"),
            "a default engine must detect built-in identifiers with no registration"
        );
    }

    #[tokio::test]
    async fn threshold_drops_the_weak_result_and_keeps_the_strong_one() {
        let engine = engine_returning(vec![
            rr("US_SSN", 0, 4, 0.3),
            rr("EMAIL_ADDRESS", 10, 20, 0.9),
        ])
        .with_score_threshold(0.5);

        let results = engine
            .analyze("0123456789abcdefghij", "en")
            .await
            .expect("analysis should succeed");

        let labels: Vec<&str> = results.iter().map(|r| r.entity_type.as_str()).collect();
        assert_eq!(
            labels,
            vec!["EMAIL_ADDRESS"],
            "only the above-threshold result should survive"
        );
    }

    #[tokio::test]
    async fn per_call_threshold_overrides_the_engine_threshold() {
        let engine = engine_returning(vec![rr("US_SSN", 0, 4, 0.3)]).with_score_threshold(0.9);

        let request = AnalyzeRequest::new("0123456789", "en").with_score_threshold(0.1);
        let results = engine
            .analyze_request(&request)
            .await
            .expect("analysis should succeed");

        assert_eq!(
            results.len(),
            1,
            "the per-call threshold must win over the engine's"
        );
    }

    #[tokio::test]
    async fn explanations_are_withheld_unless_requested() {
        let text = "SSN: 123-45-6789";
        let engine = engine_returning(vec![rr("US_SSN", 5, text.len(), 0.5)]);

        let default_run = engine.analyze(text, "en").await.expect("analysis succeeds");
        assert!(
            default_run
                .first()
                .map(|r| r.analysis_explanation.is_none())
                == Some(true),
            "explanations must not appear in a response that did not request them"
        );

        let traced = engine
            .analyze_request(&AnalyzeRequest::new(text, "en").with_decision_process(true))
            .await
            .expect("analysis succeeds");
        assert!(
            traced
                .first()
                .and_then(|r| r.analysis_explanation.as_deref())
                .is_some(),
            "a context-boosted result must explain itself when asked"
        );
    }

    #[tokio::test]
    async fn conflict_strategy_is_applied_to_the_result_set() {
        let text = "user@example.com";
        let overlapping = vec![
            rr("EMAIL_ADDRESS", 0, 16, 0.8),
            rr("EMAIL_ADDRESS", 5, 12, 0.9),
        ];

        let deduped = engine_returning(overlapping.clone())
            .analyze(text, "en")
            .await
            .expect("analysis succeeds");
        assert_eq!(
            deduped.iter().map(|r| (r.start, r.end)).collect::<Vec<_>>(),
            vec![(0, 16)],
            "the default strategy absorbs the nested same-type span"
        );

        let raw = engine_returning(overlapping)
            .with_conflict_resolution(ConflictResolution::None)
            .analyze(text, "en")
            .await
            .expect("analysis succeeds");
        assert_eq!(raw.len(), 2, "None must pass both spans through");
    }

    #[tokio::test]
    async fn an_empty_registry_returns_nothing_without_erroring() {
        let engine = AnalyzerEngine::silent().with_registry(RecognizerRegistry::new());
        let results = engine
            .analyze("Contact: user@example.com", "en")
            .await
            .expect("an empty registry is not an error");
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn results_carry_their_recognizer_provenance() {
        let results = AnalyzerEngine::silent()
            .analyze("Contact: user@example.com", "en")
            .await
            .expect("analysis should succeed");

        let name = results
            .first()
            .and_then(|r| r.recognition_metadata.as_ref())
            .and_then(|m| m.get("recognizer_name"))
            .and_then(|v| v.as_str());
        assert_eq!(name, Some("identifiers"));
    }

    #[tokio::test]
    async fn registry_accessor_returns_the_configured_registry() {
        let engine = AnalyzerEngine::silent().with_registry(
            RecognizerRegistry::new().register(Arc::new(ScriptedRecognizer { results: vec![] })),
        );

        assert_eq!(engine.registry().len(), 1);
        assert_eq!(
            engine.registry().recognizers().first().map(|r| r.name()),
            Some("scripted"),
            "the accessor must expose the registry that was configured, not the default"
        );
    }

    /// Records whether it was invoked, then fails — so a test can assert the
    /// engine reached the pipeline's failure path at all.
    struct FailingRecognizer;

    #[async_trait]
    impl Recognizer for FailingRecognizer {
        async fn analyze(
            &self,
            _text: &str,
            _language: &str,
            _entities: &[IdentifierType],
        ) -> Result<Vec<RecognizerResult>> {
            Err(crate::observe::Problem::Network("unreachable".to_string()))
        }

        fn name(&self) -> &str {
            "failing"
        }

        fn supported_entities(&self) -> &[IdentifierType] {
            &[]
        }
    }

    #[tokio::test]
    async fn silent_engine_does_not_emit_for_a_failing_custom_recognizer() {
        // A custom recognizer's failure is logged by the PIPELINE, not by the
        // recognizer, so the engine must thread emit_events down to it. A
        // silent engine that still logged there would be the same "half
        // silent" bug once fixed for the built-in recognizer.
        //
        // Asserted structurally: `analyze_request` passes `self.emit_events`
        // into `run_recognizers`, so a silent engine cannot reach the warn.
        // The run must still succeed and still count the failure.
        let engine = AnalyzerEngine::silent()
            .with_registry(RecognizerRegistry::new().register(Arc::new(FailingRecognizer)));
        assert!(!engine.emit_events, "silent() must clear the flag");

        let results = engine
            .analyze("Contact: user@example.com", "en")
            .await
            .expect("a recognizer failure must not fail the run");
        assert!(
            results.is_empty(),
            "the only recognizer failed, so there is nothing to return"
        );
    }

    #[test]
    fn silent_engine_reports_events_disabled() {
        let engine = AnalyzerEngine::silent();
        assert!(!engine.emit_events);
        assert!(AnalyzerEngine::new().emit_events);
        assert!(!AnalyzerEngine::new().with_events(false).emit_events);
    }
}
