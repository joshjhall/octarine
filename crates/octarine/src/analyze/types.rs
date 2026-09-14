//! Request and explanation types for the Layer 3 `analyze` pipeline.
//!
//! [`AnalyzeRequest`] is the per-call knob set for
//! [`AnalyzerEngine::analyze_request`](crate::analyze::AnalyzerEngine::analyze_request);
//! [`AnalysisExplanation`] is the decision-process record describing *why* a
//! detection carries the score it does.
//!
//! # Deliberately absent fields
//!
//! Presidio's `analyze()` takes a wider knob set than this one — allow-list,
//! ad-hoc recognizers, per-entity thresholds, regex flags. Those are **not**
//! stubbed here. A field that parses and validates but reaches no consumer is
//! a silent no-op: callers set it, nothing happens, and the bug surfaces only
//! in production output. Each knob lands with the pass that reads it, tracked
//! as its own issue (see [`crate::analyze`] for the roadmap).

use std::fmt;

use crate::primitives::identifiers::types::IdentifierType;

/// Per-call configuration for one analysis run.
///
/// Construct with [`AnalyzeRequest::new`] and narrow with the `with_*`
/// builders. The defaults — every supported entity, no threshold override, no
/// decision process returned — match a bare
/// [`AnalyzerEngine::analyze`](crate::analyze::AnalyzerEngine::analyze) call.
///
/// # Examples
///
/// ```
/// use octarine::analyze::AnalyzeRequest;
/// use octarine::identifiers::IdentifierType;
///
/// let request = AnalyzeRequest::new("SSN: 123-45-6789", "en")
///     .with_entities(vec![IdentifierType::Ssn])
///     .with_score_threshold(0.6)
///     .with_decision_process(true);
///
/// assert_eq!(request.language(), "en");
/// assert_eq!(request.score_threshold(), Some(0.6));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzeRequest {
    text: String,
    language: String,
    entities: Vec<IdentifierType>,
    score_threshold: Option<f64>,
    return_decision_process: bool,
}

impl AnalyzeRequest {
    /// Creates a request for `text` in `language`.
    ///
    /// `language` is a BCP 47 tag (`"en"`, `"pt-BR"`). The entity set starts
    /// empty, which means **every** type the registry's recognizers support —
    /// not "no types". This matches
    /// [`Recognizer::analyze`](crate::analyze::Recognizer::analyze)'s
    /// treatment of its `entities` argument.
    pub fn new(text: impl Into<String>, language: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            language: language.into(),
            entities: Vec::new(),
            score_threshold: None,
            return_decision_process: false,
        }
    }

    /// Narrows the run to `entities`.
    ///
    /// An empty vector restores the default of "every supported type".
    #[must_use]
    pub fn with_entities(mut self, entities: Vec<IdentifierType>) -> Self {
        self.entities = entities;
        self
    }

    /// Overrides the engine's score threshold for this call.
    ///
    /// Results scoring strictly below the threshold are dropped. Values
    /// outside `[0.0, 1.0]` are clamped when the threshold is applied, so a
    /// nonsensical override degrades to "keep everything" or "keep nothing"
    /// rather than erroring mid-pipeline.
    #[must_use]
    pub fn with_score_threshold(mut self, threshold: f64) -> Self {
        self.score_threshold = Some(threshold);
        self
    }

    /// Requests that per-result explanations survive into the output.
    ///
    /// When `false` (the default), the pipeline strips
    /// [`RecognizerResult::analysis_explanation`](crate::anonymize::RecognizerResult::analysis_explanation)
    /// from every returned result.
    #[must_use]
    pub fn with_decision_process(mut self, enabled: bool) -> Self {
        self.return_decision_process = enabled;
        self
    }

    /// The text being analyzed.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The BCP 47 language tag for this run.
    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The requested entity types; empty means "everything".
    #[must_use]
    pub fn entities(&self) -> &[IdentifierType] {
        &self.entities
    }

    /// The per-call score threshold override, if any.
    #[must_use]
    pub fn score_threshold(&self) -> Option<f64> {
        self.score_threshold
    }

    /// Whether explanations survive into the returned results.
    #[must_use]
    pub fn return_decision_process(&self) -> bool {
        self.return_decision_process
    }
}

/// Why a detection carries the score it does.
///
/// Rendered into
/// [`RecognizerResult::analysis_explanation`](crate::anonymize::RecognizerResult::analysis_explanation)
/// — an `Option<String>` — via [`Display`](fmt::Display). That field is
/// deliberately left as a string: it is shared with the anonymizer surface,
/// and promoting it to a structured type is its own tracked change.
///
/// # Examples
///
/// ```
/// use octarine::analyze::AnalysisExplanation;
///
/// let plain = AnalysisExplanation::new("identifiers", 0.5);
/// assert_eq!(plain.score(), 0.5);
/// assert_eq!(plain.to_string(), "identifiers: score 0.50");
///
/// // A context keyword near the match raises the score, and the word that
/// // did it is recorded.
/// let boosted = plain.with_context_boost("ssn", 0.85);
/// assert_eq!(boosted.original_score(), 0.5);
/// assert_eq!(boosted.score(), 0.85);
/// assert_eq!(
///     boosted.to_string(),
///     "identifiers: score 0.50 -> 0.85 (context word \"ssn\", +0.35)",
/// );
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisExplanation {
    recognizer: String,
    original_score: f64,
    score: f64,
    supportive_context_word: Option<String>,
}

impl AnalysisExplanation {
    /// Records a detection by `recognizer` at `score`, before any enhancement.
    pub fn new(recognizer: impl Into<String>, score: f64) -> Self {
        Self {
            recognizer: recognizer.into(),
            original_score: score,
            score,
            supportive_context_word: None,
        }
    }

    /// Records that `word` was found near the match and raised the score.
    ///
    /// `original_score` is preserved, so the delta stays auditable: the point
    /// of the record is showing what the score *would* have been.
    #[must_use]
    pub fn with_context_boost(mut self, word: impl Into<String>, boosted: f64) -> Self {
        self.supportive_context_word = Some(word.into());
        self.score = boosted;
        self
    }

    /// The recognizer that produced the detection.
    #[must_use]
    pub fn recognizer(&self) -> &str {
        &self.recognizer
    }

    /// The score before context enhancement.
    #[must_use]
    pub fn original_score(&self) -> f64 {
        self.original_score
    }

    /// The score after context enhancement.
    #[must_use]
    pub fn score(&self) -> f64 {
        self.score
    }

    /// The context keyword that raised the score, if one was found.
    #[must_use]
    pub fn supportive_context_word(&self) -> Option<&str> {
        self.supportive_context_word.as_deref()
    }

    /// How much context enhancement changed the score.
    ///
    /// Zero when no supportive word was found.
    #[must_use]
    pub fn score_improvement(&self) -> f64 {
        self.score - self.original_score
    }
}

impl fmt::Display for AnalysisExplanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: score {:.2}", self.recognizer, self.original_score)?;
        if let Some(word) = &self.supportive_context_word {
            write!(
                f,
                " -> {:.2} (context word {:?}, {:+.2})",
                self.score,
                word,
                self.score_improvement()
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn request_defaults_to_all_entities_and_no_threshold() {
        let request = AnalyzeRequest::new("text", "en");
        assert!(
            request.entities().is_empty(),
            "empty entity set means everything, not nothing"
        );
        assert_eq!(request.score_threshold(), None);
        assert!(!request.return_decision_process());
    }

    #[test]
    fn request_builders_set_exactly_their_own_field() {
        let request = AnalyzeRequest::new("text", "fr")
            .with_entities(vec![IdentifierType::Email])
            .with_score_threshold(0.75)
            .with_decision_process(true);

        assert_eq!(request.text(), "text");
        assert_eq!(request.language(), "fr");
        assert_eq!(request.entities(), &[IdentifierType::Email]);
        assert_eq!(request.score_threshold(), Some(0.75));
        assert!(request.return_decision_process());
    }

    #[test]
    fn with_entities_empty_restores_everything() {
        let request = AnalyzeRequest::new("text", "en")
            .with_entities(vec![IdentifierType::Ssn])
            .with_entities(Vec::new());
        assert!(request.entities().is_empty());
    }

    #[test]
    fn explanation_without_boost_reports_zero_improvement() {
        let explanation = AnalysisExplanation::new("identifiers", 0.5);
        assert_eq!(explanation.recognizer(), "identifiers");
        assert_eq!(explanation.original_score(), 0.5);
        assert_eq!(explanation.score(), 0.5);
        assert_eq!(explanation.supportive_context_word(), None);
        assert!(explanation.score_improvement().abs() < f64::EPSILON);
    }

    #[test]
    fn context_boost_preserves_original_score() {
        let explanation =
            AnalysisExplanation::new("identifiers", 0.5).with_context_boost("ssn", 0.85);

        assert_eq!(
            explanation.original_score(),
            0.5,
            "the pre-boost score must survive — it is the whole point of the record"
        );
        assert_eq!(explanation.score(), 0.85);
        assert_eq!(explanation.supportive_context_word(), Some("ssn"));
        assert!((explanation.score_improvement() - 0.35).abs() < 1e-9);
    }

    #[test]
    fn display_omits_boost_clause_when_unboosted() {
        let rendered = AnalysisExplanation::new("identifiers", 0.5).to_string();
        assert_eq!(rendered, "identifiers: score 0.50");
        assert!(
            !rendered.contains("context word"),
            "an unboosted explanation must not claim a context word"
        );
    }

    #[test]
    fn display_names_the_supportive_word_and_delta() {
        let rendered = AnalysisExplanation::new("identifiers", 0.5)
            .with_context_boost("ssn", 0.85)
            .to_string();
        assert_eq!(
            rendered,
            "identifiers: score 0.50 -> 0.85 (context word \"ssn\", +0.35)"
        );
    }
}
