//! [`Recognizer`] adapter over octarine's built-in identifier detection.
//!
//! [`IdentifierRecognizer`] is what makes [`AnalyzerEngine`] useful with no
//! registration at all: it wraps
//! [`Identifiers::scan_text`](crate::identifiers::Identifiers::scan_text) — the
//! full multi-domain identifier scan — behind the pluggable
//! [`Recognizer`] interface, so the built-in detectors and a customer's own
//! recognizer are driven by the same pipeline.
//!
//! [`AnalyzerEngine`]: crate::analyze::AnalyzerEngine

use async_trait::async_trait;

use crate::analyze::Recognizer;
use crate::analyze::pipeline::mark_context_enhanced;
use crate::anonymize::RecognizerResult;
use crate::identifiers::IdentifierBuilder;
use crate::observe;
use crate::observe::Result;
use crate::primitives::identifiers::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

/// Score for a [`DetectionConfidence::Low`] match — a heuristic hit.
const SCORE_LOW: f64 = 0.4;
/// Score for a [`DetectionConfidence::Medium`] match — a pattern match.
const SCORE_MEDIUM: f64 = 0.6;
/// Score for a [`DetectionConfidence::High`] match — pattern plus validation
/// (a checksum, a Luhn digit, a structural rule).
const SCORE_HIGH: f64 = 0.85;

/// Maps octarine's three-level confidence onto the `[0.0, 1.0]` score
/// [`RecognizerResult`] carries.
///
/// The three levels mean *how the detection was reached*, not a probability:
/// [`Low`](DetectionConfidence::Low) is a heuristic, `Medium` a pattern match,
/// `High` a pattern match that also passed validation. The mapping is
/// deliberately spread so a default engine threshold can separate them, and
/// `High` stops short of `1.0` — a passing checksum is strong evidence, not
/// certainty, and leaving headroom lets context enhancement raise a score
/// without saturating.
#[must_use]
const fn score_for(confidence: DetectionConfidence) -> f64 {
    match confidence {
        DetectionConfidence::Low => SCORE_LOW,
        DetectionConfidence::Medium => SCORE_MEDIUM,
        DetectionConfidence::High => SCORE_HIGH,
    }
}

/// Converts scan matches into results, narrowed to `entities`.
///
/// Split out of [`IdentifierRecognizer::analyze`] so the malformed-span path
/// is reachable from a test: driving it through a real scan would require
/// finding text that makes the scanner emit a bad span, which is exactly the
/// thing that should never happen.
///
/// # Failure handling
///
/// A match that does not survive [`RecognizerResult::new`]'s validation (an
/// inverted span, an out-of-range score) is logged and **dropped**, and the
/// remaining matches are returned. Failing the whole conversion instead would
/// mean one bad span silently zeroes out every built-in detection for the
/// call — [`IdentifierRecognizer`] is the sole default-registered recognizer,
/// and [`run_recognizers`](crate::analyze) skips a recognizer that errors. For
/// a PII detector, a false negative is the costlier error.
fn convert_matches(
    matches: Vec<IdentifierMatch>,
    entities: &[IdentifierType],
    emit_events: bool,
) -> Vec<RecognizerResult> {
    let mut out = Vec::with_capacity(matches.len());
    for m in matches {
        // An empty request means "everything" — not "nothing".
        if !entities.is_empty() && !entities.contains(&m.identifier_type) {
            continue;
        }
        let label = m.identifier_type.as_str();
        match RecognizerResult::new(label, m.start, m.end, score_for(m.confidence)) {
            Ok(mut result) => {
                // scan_text has already folded context into `confidence`, so
                // the score arriving here is context-aware. Mark it, or the
                // engine's enhancement pass counts the same keyword again.
                mark_context_enhanced(&mut result);
                out.push(result);
            }
            Err(problem) => {
                if emit_events {
                    observe::warn(
                        "analyze_identifier_span_rejected",
                        format!("Dropping malformed {label} span: {problem}"),
                    );
                }
            }
        }
    }
    out
}

/// Detects every identifier type octarine knows about.
///
/// # Language handling
///
/// The underlying identifier scan is **language-agnostic** — a credit card
/// number looks the same in every locale — so this recognizer accepts any
/// language tag rather than returning an empty set for unfamiliar ones, and
/// the tag is otherwise **ignored**.
///
/// It is not forwarded as a keyword-language hint, because
/// [`scan_text`](crate::identifiers::Identifiers::scan_text) takes no language
/// and scans every language's keyword table. Threading one through is a change
/// to that API rather than to this adapter.
///
/// # Scoring
///
/// `scan_text` folds context into each match's confidence before this
/// recognizer sees it, so every result is marked context-enhanced and the
/// engine's own enhancement pass skips it. Without that marker the same nearby
/// keyword would raise the score twice — once inside the scan, once in the
/// pipeline — and a heuristic hit next to a label would end up scoring like a
/// checksum-validated one.
///
/// # Examples
///
/// ```
/// use octarine::analyze::{IdentifierRecognizer, Recognizer};
///
/// # tokio_test::block_on(async {
/// let recognizer = IdentifierRecognizer::new();
/// let results = recognizer.analyze("Email: user@example.com", "en", &[]).await?;
///
/// assert!(results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"));
/// # Ok::<(), octarine::observe::Problem>(())
/// # }).unwrap();
/// ```
#[derive(Debug, Clone, Copy)]
pub struct IdentifierRecognizer {
    builder: IdentifierBuilder,
    emit_events: bool,
}

impl Default for IdentifierRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentifierRecognizer {
    /// Creates a recognizer over the default identifier scan.
    #[must_use]
    pub fn new() -> Self {
        Self {
            builder: IdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Creates a recognizer that emits no observe events or metrics.
    ///
    /// Silence propagates into the underlying scan, not just this adapter's
    /// own logging — a half-silent recognizer still floods the dispatcher from
    /// the layer below, which is the part that actually emits per match.
    #[must_use]
    pub fn silent() -> Self {
        Self {
            builder: IdentifierBuilder::silent(),
            emit_events: false,
        }
    }

    /// Toggles observe event and metric emission.
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.builder = self.builder.with_events(emit);
        self.emit_events = emit;
        self
    }
}

#[async_trait]
impl Recognizer for IdentifierRecognizer {
    async fn analyze(
        &self,
        text: &str,
        _language: &str,
        entities: &[IdentifierType],
    ) -> Result<Vec<RecognizerResult>> {
        Ok(convert_matches(
            self.builder.scan_text(text),
            entities,
            self.emit_events,
        ))
    }

    fn name(&self) -> &str {
        "identifiers"
    }

    /// Returns an empty slice, which by the [`Recognizer`] contract advertises
    /// **every** type — this recognizer covers octarine's whole identifier
    /// catalog and enumerating all 100+ variants here would be a second copy
    /// of the registry that could drift from the first.
    fn supported_entities(&self) -> &[IdentifierType] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn detects_email_with_presidio_entity_label() {
        let results = IdentifierRecognizer::new()
            .analyze("Contact: user@example.com", "en", &[])
            .await
            .expect("scan should succeed");

        let email = results
            .iter()
            .find(|r| r.entity_type == "EMAIL_ADDRESS")
            .expect("email should be detected under its Presidio label");
        assert_eq!(
            &"Contact: user@example.com"[email.start..email.end],
            "user@example.com"
        );
    }

    #[tokio::test]
    async fn entity_filter_excludes_other_types() {
        let text = "Email user@example.com and IP 192.168.1.1";
        let results = IdentifierRecognizer::new()
            .analyze(text, "en", &[IdentifierType::Email])
            .await
            .expect("scan should succeed");

        assert!(
            results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"),
            "the requested type must survive the filter"
        );
        assert!(
            !results.iter().any(|r| r.entity_type == "IP_ADDRESS"),
            "an unrequested type must be filtered out, got {:?}",
            results.iter().map(|r| &r.entity_type).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn empty_entity_set_means_everything() {
        let text = "Email user@example.com and IP 192.168.1.1";
        let all = IdentifierRecognizer::new()
            .analyze(text, "en", &[])
            .await
            .expect("scan should succeed");

        assert!(
            all.len() >= 2,
            "empty request must not be read as 'no types'; got {} results",
            all.len()
        );
    }

    #[tokio::test]
    async fn unknown_language_still_detects() {
        // Identifier patterns are language-agnostic; an unfamiliar tag must not
        // silently suppress detection.
        let results = IdentifierRecognizer::new()
            .analyze("Email: user@example.com", "xx-ZZ", &[])
            .await
            .expect("scan should succeed");

        assert!(
            results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"),
            "an unrecognized language tag must degrade to detecting, not to nothing"
        );
    }

    /// Builds a scan match over `[start, end)`.
    fn im(start: usize, end: usize, identifier_type: IdentifierType) -> IdentifierMatch {
        im_with(start, end, identifier_type, DetectionConfidence::High)
    }

    /// Builds a scan match at a chosen confidence level.
    fn im_with(
        start: usize,
        end: usize,
        identifier_type: IdentifierType,
        confidence: DetectionConfidence,
    ) -> IdentifierMatch {
        IdentifierMatch::new(start, end, "value".to_string(), identifier_type, confidence)
    }

    #[test]
    fn a_malformed_span_does_not_discard_the_other_matches() {
        // The middle match is inverted (start > end), which
        // RecognizerResult::new rejects. Only it may be lost.
        let matches = vec![
            im(0, 16, IdentifierType::Email),
            im(20, 10, IdentifierType::Ssn),
            im(30, 41, IdentifierType::IpAddress),
        ];

        let out = convert_matches(matches, &[], false);

        let labels: Vec<&str> = out.iter().map(|r| r.entity_type.as_str()).collect();
        assert_eq!(
            labels,
            vec!["EMAIL_ADDRESS", "IP_ADDRESS"],
            "the malformed span must be dropped and BOTH well-formed spans kept — \
             propagating instead would return neither"
        );
    }

    #[test]
    fn converted_results_are_marked_context_enhanced() {
        // Without this marker the pipeline's enhancement pass would add a
        // second boost on top of the one scan_text already folded in.
        let out = convert_matches(vec![im(0, 16, IdentifierType::Email)], &[], false);

        let marked = out
            .first()
            .and_then(|r| r.recognition_metadata.as_ref())
            .and_then(|m| m.get("is_score_enhanced_by_context"))
            .and_then(serde_json::Value::as_bool);
        assert_eq!(
            marked,
            Some(true),
            "scan_text already applied context, so the result must say so"
        );
    }

    #[test]
    fn every_confidence_level_is_marked_context_enhanced() {
        // A Low-confidence heuristic hit is exactly the case a second boost
        // would saturate toward the ceiling, so it must carry the marker too.
        for confidence in [
            DetectionConfidence::Low,
            DetectionConfidence::Medium,
            DetectionConfidence::High,
        ] {
            let out = convert_matches(
                vec![im_with(0, 16, IdentifierType::Email, confidence.clone())],
                &[],
                false,
            );
            let marked = out
                .first()
                .and_then(|r| r.recognition_metadata.as_ref())
                .and_then(|m| m.get("is_score_enhanced_by_context"))
                .and_then(serde_json::Value::as_bool);
            assert_eq!(marked, Some(true), "unmarked at {confidence:?}");
        }
    }

    #[test]
    fn a_malformed_span_is_dropped_rather_than_emitted() {
        let out = convert_matches(vec![im(20, 10, IdentifierType::Ssn)], &[], false);
        assert!(
            out.is_empty(),
            "an inverted span cannot be represented; it must not reach the pipeline"
        );
    }

    #[test]
    fn confidence_levels_map_to_distinct_increasing_scores() {
        assert!(score_for(DetectionConfidence::Low) < score_for(DetectionConfidence::Medium));
        assert!(score_for(DetectionConfidence::Medium) < score_for(DetectionConfidence::High));
        assert!(
            score_for(DetectionConfidence::High) < 1.0,
            "High must leave headroom for context enhancement"
        );
    }

    #[tokio::test]
    async fn silent_mode_reaches_the_underlying_scan() {
        // A half-silent recognizer — quiet in this adapter but loud in the
        // scan below it — is the failure mode this guards: the scan emits per
        // match, so it is the layer that actually matters.
        let silent = IdentifierRecognizer::silent();
        assert!(!silent.emit_events);

        let results = silent
            .analyze("Contact: user@example.com", "en", &[])
            .await
            .expect("silent mode must still detect");
        assert!(
            results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"),
            "silencing observability must not silence detection"
        );

        assert!(IdentifierRecognizer::new().emit_events);
        assert!(!IdentifierRecognizer::new().with_events(false).emit_events);
    }

    #[test]
    fn supported_entities_is_empty_meaning_everything() {
        let recognizer = IdentifierRecognizer::new();
        assert!(recognizer.supported_entities().is_empty());
        assert!(
            recognizer.supports(&[IdentifierType::Ssn]),
            "empty supported_entities must advertise everything, not nothing"
        );
    }
}
