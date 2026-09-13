//! End-to-end tests for the Layer 3 `analyze` pipeline.
//!
//! These exercise the public surface only — what a consumer can reach — and
//! cover the paths that span several passes, which the per-pass unit tests
//! inside the module cannot.

#![allow(clippy::panic, clippy::expect_used)]

use std::sync::Arc;

use async_trait::async_trait;

use octarine::analyze::{
    AnalyzeRequest, AnalyzerEngine, ConflictResolution, Recognizer, RecognizerRegistry, analyze,
};
use octarine::anonymize::RecognizerResult;
use octarine::identifiers::IdentifierType;
use octarine::observe::{Problem, Result};

/// Emits a fixed result set, regardless of input.
struct ScriptedRecognizer {
    label: &'static str,
    supported: Vec<IdentifierType>,
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
        self.label
    }

    fn supported_entities(&self) -> &[IdentifierType] {
        &self.supported
    }
}

/// Always fails — an unreachable remote PII service.
struct UnreachableRecognizer;

#[async_trait]
impl Recognizer for UnreachableRecognizer {
    async fn analyze(
        &self,
        _text: &str,
        _language: &str,
        _entities: &[IdentifierType],
    ) -> Result<Vec<RecognizerResult>> {
        Err(Problem::Network("service unavailable".to_string()))
    }

    fn name(&self) -> &str {
        "unreachable"
    }

    fn supported_entities(&self) -> &[IdentifierType] {
        &[]
    }
}

fn rr(entity_type: &str, start: usize, end: usize, score: f64) -> RecognizerResult {
    RecognizerResult::new(entity_type, start, end, score).expect("valid test result")
}

fn labels(results: &[RecognizerResult]) -> Vec<&str> {
    results.iter().map(|r| r.entity_type.as_str()).collect()
}

#[tokio::test]
async fn default_engine_detects_multiple_identifier_types() {
    let text = "Email user@example.com or call 212-555-0123";
    let results = AnalyzerEngine::new()
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");

    let found = labels(&results);
    assert!(
        found.contains(&"EMAIL_ADDRESS"),
        "expected an email detection, got {found:?}"
    );
    assert!(
        found.contains(&"PHONE_NUMBER"),
        "expected a phone detection, got {found:?}"
    );
}

#[tokio::test]
async fn spans_index_the_original_text_correctly() {
    let text = "Email user@example.com now";
    let results = AnalyzerEngine::new()
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");

    let email = results
        .iter()
        .find(|r| r.entity_type == "EMAIL_ADDRESS")
        .expect("email should be detected");
    assert_eq!(
        text.get(email.start..email.end),
        Some("user@example.com"),
        "a span that does not slice back to the detected value is unusable downstream"
    );
}

#[tokio::test]
async fn a_custom_recognizer_runs_alongside_the_built_in_one() {
    let text = "Order ACME-42 for user@example.com";
    let custom = Arc::new(ScriptedRecognizer {
        label: "order-ids",
        supported: Vec::new(),
        results: vec![rr("ORDER_ID", 6, 13, 0.9)],
    });

    let registry = RecognizerRegistry::with_defaults().register(custom);
    let results = AnalyzerEngine::new()
        .with_registry(registry)
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");

    let found = labels(&results);
    assert!(
        found.contains(&"ORDER_ID"),
        "the custom recognizer's result must appear, got {found:?}"
    );
    assert!(
        found.contains(&"EMAIL_ADDRESS"),
        "the built-in recognizer must still run, got {found:?}"
    );
}

#[tokio::test]
async fn a_failing_recognizer_does_not_lose_the_other_results() {
    let text = "Email user@example.com";
    let registry = RecognizerRegistry::with_defaults().register(Arc::new(UnreachableRecognizer));

    let results = AnalyzerEngine::new()
        .with_registry(registry)
        .analyze(text, "en")
        .await
        .expect("one recognizer failing must not fail the run");

    assert!(
        labels(&results).contains(&"EMAIL_ADDRESS"),
        "a degraded run must still return what the healthy recognizers found"
    );
}

#[tokio::test]
async fn entity_narrowing_excludes_other_detections() {
    let text = "Email user@example.com or call 212-555-0123";
    let request = AnalyzeRequest::new(text, "en").with_entities(vec![IdentifierType::Email]);

    let results = AnalyzerEngine::new()
        .analyze_request(&request)
        .await
        .expect("analysis should succeed");

    let found = labels(&results);
    assert!(
        found.contains(&"EMAIL_ADDRESS"),
        "the requested type must be returned, got {found:?}"
    );
    assert!(
        !found.contains(&"PHONE_NUMBER"),
        "an unrequested type must not appear, got {found:?}"
    );
}

#[tokio::test]
async fn conflict_strategy_changes_which_span_survives() {
    // A phone number nested inside a longer URL-shaped span.
    let text = "https://x.example/555-867-5309";
    let overlapping = vec![rr("URL", 0, 30, 0.8), rr("PHONE_NUMBER", 18, 30, 0.9)];

    let scripted = |results: Vec<RecognizerResult>| {
        RecognizerRegistry::new().register(Arc::new(ScriptedRecognizer {
            label: "scripted",
            supported: Vec::new(),
            results,
        }))
    };

    let same_type = AnalyzerEngine::silent()
        .with_registry(scripted(overlapping.clone()))
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");
    assert_eq!(
        labels(&same_type),
        vec!["URL", "PHONE_NUMBER"],
        "same-type containment (Presidio parity) keeps a cross-type nested span"
    );

    let cross_type = AnalyzerEngine::silent()
        .with_registry(scripted(overlapping))
        .with_conflict_resolution(ConflictResolution::CrossTypeContainment)
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");
    assert_eq!(
        labels(&cross_type),
        vec!["URL"],
        "cross-type containment absorbs the nested span"
    );
}

#[tokio::test]
async fn threshold_excludes_weak_detections_end_to_end() {
    let text = "Email user@example.com";

    let unfiltered = AnalyzerEngine::silent()
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");
    assert!(
        !unfiltered.is_empty(),
        "fixture must detect something, or the comparison below is vacuous"
    );

    let filtered = AnalyzerEngine::silent()
        .with_score_threshold(0.99)
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");

    assert!(
        filtered.len() < unfiltered.len(),
        "a 0.99 threshold must exclude detections the unfiltered run returned \
         ({} vs {})",
        filtered.len(),
        unfiltered.len()
    );
    assert!(
        filtered.iter().all(|r| r.score >= 0.99),
        "nothing below the threshold may survive"
    );
}

#[tokio::test]
async fn results_are_traceable_to_their_recognizer() {
    let results = AnalyzerEngine::silent()
        .analyze("Email user@example.com", "en")
        .await
        .expect("analysis should succeed");

    let email = results
        .iter()
        .find(|r| r.entity_type == "EMAIL_ADDRESS")
        .expect("email should be detected");
    let recognizer = email
        .recognition_metadata
        .as_ref()
        .and_then(|m| m.get("recognizer_name"))
        .and_then(|v| v.as_str());
    assert_eq!(
        recognizer,
        Some("identifiers"),
        "every result must name the recognizer that produced it"
    );
}

#[tokio::test]
async fn decision_process_is_opt_in() {
    // A scripted recognizer, not the built-in one: results from
    // IdentifierRecognizer arrive already context-enhanced by the scan, so the
    // engine's enhancement pass deliberately skips them and produces no
    // explanation. This recognizer's results are not pre-enhanced, so the
    // boost — and its explanation — do happen.
    let text = "SSN: 412-77-3856";
    let registry = || {
        RecognizerRegistry::new().register(Arc::new(ScriptedRecognizer {
            label: "scripted",
            supported: Vec::new(),
            results: vec![rr("US_SSN", 5, text.len(), 0.5)],
        }))
    };

    let default_run = AnalyzerEngine::silent()
        .with_registry(registry())
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");
    assert!(
        default_run.iter().all(|r| r.analysis_explanation.is_none()),
        "explanations must not leak into a response that did not ask for them"
    );

    let traced = AnalyzerEngine::silent()
        .with_registry(registry())
        .analyze_request(&AnalyzeRequest::new(text, "en").with_decision_process(true))
        .await
        .expect("analysis should succeed");
    assert!(
        traced.iter().any(|r| r.analysis_explanation.is_some()),
        "a context-boosted detection must explain itself when asked"
    );
}

#[tokio::test]
async fn context_enhancement_runs_before_thresholding() {
    // The pass order is load-bearing: a result scoring UNDER the threshold on
    // its own, but over it once a nearby keyword boosts it, must survive. If
    // thresholding ran first the rescue would come too late and this detection
    // would be gone. 0.5 + 0.35 = 0.85, so it clears a 0.6 threshold only via
    // the boost.
    let text = "SSN: 412-77-3856";
    let registry = RecognizerRegistry::new().register(Arc::new(ScriptedRecognizer {
        label: "scripted",
        supported: Vec::new(),
        results: vec![rr("US_SSN", 5, text.len(), 0.5)],
    }));

    let results = AnalyzerEngine::silent()
        .with_registry(registry)
        .with_score_threshold(0.6)
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");

    assert_eq!(
        labels(&results),
        vec!["US_SSN"],
        "a detection the context rescued must survive the threshold — \
         thresholding before enhancement would have dropped it"
    );
}

#[tokio::test]
async fn built_in_detections_are_not_context_boosted_twice() {
    // scan_text already folds context into confidence. If the engine boosted
    // again, this heuristic-adjacent match would saturate toward 0.95 and be
    // indistinguishable from a checksum-validated detection.
    let text = "SSN: 412-77-3856";
    let results = AnalyzerEngine::silent()
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");

    let detection = results
        .iter()
        .find(|r| r.entity_type == "US_SSN")
        .expect("the identifier should be detected");
    // The score is deliberately NOT interpolated: this file's fixtures are
    // identifier-shaped, and an assertion message is a cleartext-logging sink.
    assert!(
        detection.score <= 0.85,
        "a single context signal must be counted once; a second boost would push \
         the score past the confidence-derived ceiling"
    );
}

#[tokio::test]
async fn context_keyword_raises_the_score() {
    // The same SSN, with and without a supportive "SSN:" prefix.
    let bare = AnalyzerEngine::silent()
        .analyze("Ref 412-77-3856 filed", "en")
        .await
        .expect("analysis should succeed");
    let in_context = AnalyzerEngine::silent()
        .analyze("SSN: 412-77-3856", "en")
        .await
        .expect("analysis should succeed");

    let score_of = |results: &[RecognizerResult]| -> Option<f64> {
        results
            .iter()
            .find(|r| r.entity_type == "US_SSN")
            .map(|r| r.score)
    };

    let bare_score = score_of(&bare).expect("SSN should be detected without context");
    let context_score = score_of(&in_context).expect("SSN should be detected with context");
    assert!(
        context_score > bare_score,
        "a supportive keyword must raise the score"
    );
}

#[tokio::test]
async fn unknown_language_tag_still_detects() {
    let results = analyze("Email user@example.com", "xx-ZZ")
        .await
        .expect("analysis should succeed");

    assert!(
        labels(&results).contains(&"EMAIL_ADDRESS"),
        "an unrecognized language tag must degrade to detecting, not to nothing"
    );
}

#[tokio::test]
async fn empty_text_yields_no_results_without_erroring() {
    let results = analyze("", "en")
        .await
        .expect("empty input is not an error");
    assert!(results.is_empty());
}

#[tokio::test]
async fn results_flow_into_the_anonymizer_unchanged() {
    use std::collections::HashMap;

    use octarine::anonymize::AnonymizerEngine;

    let text = "Email user@example.com";
    let results = AnalyzerEngine::silent()
        .analyze(text, "en")
        .await
        .expect("analysis should succeed");

    // The whole point of one shared RecognizerResult type: no conversion.
    let anonymized = AnonymizerEngine::new()
        .anonymize(text, results, &HashMap::new())
        .expect("anonymization should succeed");

    let out = anonymized.text.as_deref().expect("output text");
    assert!(
        !out.contains("user@example.com"),
        "the detected email must not survive anonymization, got {out:?}"
    );
    assert!(
        out.contains("<EMAIL_ADDRESS>"),
        "the span should be replaced with its entity placeholder, got {out:?}"
    );
}
