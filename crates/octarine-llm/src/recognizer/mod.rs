//! [`LLMRecognizer`] — an [`Recognizer`] backed by a language model.

pub mod config;
pub mod loader;
pub mod parse;
pub mod prompt;

use async_trait::async_trait;
use octarine::analyze::Recognizer;
use octarine::anonymize::RecognizerResult;
use octarine::identifiers::IdentifierType;
use octarine::observe;
use octarine::observe::metrics::{increment, increment_by, record};
use octarine_problem::Result;

use std::collections::HashMap;

use crate::metrics::{self, Outcome, metric_names};
use crate::recognizer::config::ConfidencePolicy;
use crate::types::{LlmProvider, LlmRequest};

/// Default ceiling on generated tokens.
///
/// Detection output is a JSON list whose size scales with the number of
/// entities, not with input length. 2048 covers a densely-populated document
/// while still bounding a runaway generation.
const DEFAULT_MAX_TOKENS: u32 = 2048;

/// A [`Recognizer`] that detects entities by asking a language model.
///
/// Generic over the provider so the five backends share one implementation of
/// prompting, parsing, anchoring, and instrumentation — the provider supplies
/// only transport and wire format.
///
/// # Buffered, not streaming
///
/// [`analyze`](Recognizer::analyze) calls [`LlmProvider::complete`], never
/// [`complete_streaming`](LlmProvider::complete_streaming). Detection output is
/// one JSON document, so a partial body yields no spans — there is nothing
/// useful to hand back mid-stream. Callers who want the streaming transport
/// (bounded memory, no idle timeout on a slow local model) can drive a provider
/// directly; see the crate-level docs.
///
/// # Examples
///
/// ```no_run
/// use octarine::analyze::Recognizer;
/// use octarine_llm::{LLMRecognizer, provider::OpenAiProvider};
///
/// # async fn run() -> Result<(), octarine_problem::Problem> {
/// let provider = OpenAiProvider::new("sk-...", "gpt-4o")?;
/// let recognizer = LLMRecognizer::new(provider);
///
/// let found = recognizer
///     .analyze("Contact alice@example.com", "en", &[])
///     .await?;
/// # let _ = found;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct LLMRecognizer<P: LlmProvider> {
    /// The completion backend.
    provider: P,
    /// Entity types advertised through
    /// [`supported_entities`](Recognizer::supported_entities).
    ///
    /// Empty means "everything", per that method's contract — a general-purpose
    /// LLM cannot enumerate what it can find. A registry must filter with
    /// [`Recognizer::supports`], not a bare intersection.
    supported: Vec<IdentifierType>,
    /// Ceiling on generated tokens per call.
    max_tokens: u32,
    /// Whether to emit observe events. Mirrors the Layer 3 builder convention
    /// so a caller running the recognizer in a hot loop can silence it.
    emit_events: bool,
    /// A config-supplied system prompt, replacing the built-in one.
    ///
    /// `None` keeps [`prompt::system_prompt`], which derives a prompt from the
    /// requested entity types. A TOML-configured recognizer supplies its own,
    /// which is how a config can specialize a recognizer to one entity type or
    /// one document shape.
    system_prompt: Option<String>,
    /// Model entity label → octarine type, applied to detections before
    /// anchoring. Empty means pass the model's labels through unchanged.
    entity_mapping: HashMap<String, IdentifierType>,
    /// How detections are scored. [`ConfidencePolicy::FromModel`] keeps what
    /// the model reported.
    confidence: ConfidencePolicy,
    /// Recognizer name, when a config named it. `None` falls back to the
    /// provider name, preserving the pre-config behaviour.
    name: Option<String>,
}

impl<P: LlmProvider> LLMRecognizer<P> {
    /// Builds a recognizer over `provider`, advertising every entity type.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            supported: Vec::new(),
            max_tokens: DEFAULT_MAX_TOKENS,
            emit_events: true,
            system_prompt: None,
            entity_mapping: HashMap::new(),
            confidence: ConfidencePolicy::FromModel,
            name: None,
        }
    }

    /// Restricts the entity types this recognizer advertises and requests.
    #[must_use]
    pub fn with_supported_entities(mut self, entities: Vec<IdentifierType>) -> Self {
        self.supported = entities;
        self
    }

    /// Overrides the generated-token ceiling.
    #[must_use]
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// Replaces the built-in detection prompt.
    ///
    /// The supplied prompt is used verbatim, so it must still ask for the JSON
    /// envelope [`parse`] expects — a prompt that
    /// elicits prose produces a parse failure, not a silent empty result.
    #[must_use]
    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Maps the model's entity labels onto octarine types.
    ///
    /// Applied to each detection before anchoring. A label with no mapping
    /// passes through unchanged rather than being dropped: the mapping narrows
    /// vocabulary differences, it is not an allow-list.
    #[must_use]
    pub fn with_entity_mapping(mut self, mapping: HashMap<String, IdentifierType>) -> Self {
        self.entity_mapping = mapping;
        self
    }

    /// Sets how detections are scored.
    #[must_use]
    pub fn with_confidence(mut self, confidence: ConfidencePolicy) -> Self {
        self.confidence = confidence;
        self
    }

    /// Overrides the recognizer name reported by
    /// [`Recognizer::name`].
    ///
    /// A TOML-configured recognizer uses its `class_name`, so two instances of
    /// the same provider stay distinguishable in metrics and audit records.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Disables observe event emission. Metrics are still recorded.
    #[must_use]
    pub fn silent(mut self) -> Self {
        self.emit_events = false;
        self
    }

    /// Chooses which entity types to request.
    ///
    /// An empty `requested` slice means "everything", per the [`Recognizer`]
    /// contract. Otherwise the request narrows to the intersection with the
    /// advertised set — asking a provider for types this recognizer does not
    /// support wastes prompt tokens.
    /// Rewrites each detection's label through the configured mapping.
    ///
    /// An unmapped label passes through untouched. The mapping exists to
    /// reconcile vocabulary — a model that says `PERSON` where octarine says
    /// `PERSON`, or `LOC` where octarine says `NAMED_LOCATION` — not to filter,
    /// so dropping unmapped labels would silently discard real detections from
    /// a config that merely did not enumerate every type.
    fn apply_entity_mapping(&self, raw: Vec<parse::RawEntity>) -> Vec<parse::RawEntity> {
        if self.entity_mapping.is_empty() {
            return raw;
        }
        raw.into_iter()
            .map(|mut entity| {
                if let Some(mapped) = self.entity_mapping.get(&entity.entity_type) {
                    entity.entity_type = mapped.as_str().to_string();
                }
                entity
            })
            .collect()
    }

    /// Applies the configured scoring policy to anchored detections.
    ///
    /// [`ConfidencePolicy::FromModel`] is a no-op — the score `parse::anchor`
    /// already clamped is what the model reported.
    fn apply_confidence(&self, results: &mut [RecognizerResult]) {
        let ConfidencePolicy::Constant(value) = self.confidence else {
            return;
        };
        for result in results.iter_mut() {
            result.score = value;
        }
    }

    fn resolve_entities(&self, requested: &[IdentifierType]) -> Vec<IdentifierType> {
        if requested.is_empty() {
            return self.supported.clone();
        }
        if self.supported.is_empty() {
            return requested.to_vec();
        }
        requested
            .iter()
            .filter(|e| self.supported.contains(e))
            .cloned()
            .collect()
    }
}

/// Increments the `{provider, outcome}`-dimensioned call counter.
///
/// Silently skips when the name does not validate rather than failing the
/// detection — a metric is never worth losing a result over. The undimensioned
/// `calls_total` is incremented separately, so the observation is never lost
/// entirely.
fn record_outcome(provider: &str, outcome: Outcome) {
    if let Some(name) = metrics::calls_by_provider(provider, outcome) {
        increment(name);
    }
}

#[async_trait]
impl<P: LlmProvider> Recognizer for LLMRecognizer<P> {
    async fn analyze(
        &self,
        text: &str,
        _language: &str,
        entities: &[IdentifierType],
    ) -> Result<Vec<RecognizerResult>> {
        // An empty input has no spans to find, and a provider call would bill
        // for a guaranteed-empty answer.
        if text.is_empty() {
            return Ok(Vec::new());
        }

        let requested = self.resolve_entities(entities);
        // A caller narrowing to types this recognizer does not support gets an
        // empty result, not a call asking the model for nothing.
        if !entities.is_empty() && requested.is_empty() {
            return Ok(Vec::new());
        }

        // A config-supplied prompt wins; otherwise derive one from the
        // requested entity types.
        let system = self
            .system_prompt
            .clone()
            .unwrap_or_else(|| prompt::system_prompt(&requested));
        let request = LlmRequest::for_detection(
            system,
            prompt::user_prompt(text),
            String::new(), // provider substitutes its configured model
            self.max_tokens,
        );

        let started = std::time::Instant::now();
        let outcome = self.provider.complete(&request).await;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

        increment(metric_names::calls_total());
        record(metric_names::call_duration_ms(), elapsed_ms);
        if let Some(name) = metrics::duration_by_provider(self.provider.name()) {
            record(name, elapsed_ms);
        }

        let response = match outcome {
            Ok(response) => response,
            Err(problem) => {
                increment(metric_names::errors());
                record_outcome(self.provider.name(), Outcome::ProviderError);
                if self.emit_events {
                    observe::warn(
                        "llm.recognizer.analyze",
                        format!(
                            "provider={} latency_ms={:.1} outcome=error error={}",
                            self.provider.name(),
                            elapsed_ms,
                            problem
                        ),
                    );
                }
                return Err(problem);
            }
        };

        let usage = response.usage;
        increment_by(
            metric_names::prompt_tokens(),
            u64::from(usage.prompt_tokens),
        );
        increment_by(
            metric_names::completion_tokens(),
            u64::from(usage.completion_tokens),
        );
        if let Some(cached) = usage.cache_read_tokens {
            increment_by(metric_names::cache_read_tokens(), u64::from(cached));
        }

        let raw = match parse::parse_entities(&response.content) {
            Ok(raw) => raw,
            Err(problem) => {
                increment(metric_names::parse_failures());
                record_outcome(self.provider.name(), Outcome::ParseError);
                if self.emit_events {
                    // Truncation is the usual cause, and it is actionable
                    // (raise max_tokens) in a way a generic parse error is not.
                    observe::warn(
                        "llm.recognizer.analyze",
                        format!(
                            "provider={} model={} finish_reason={:?} truncated={} outcome=parse_error error={}",
                            self.provider.name(),
                            response.model,
                            response.finish_reason,
                            response.finish_reason.is_truncated(),
                            problem
                        ),
                    );
                }
                return Err(problem);
            }
        };

        record_outcome(self.provider.name(), Outcome::Ok);

        let raw = self.apply_entity_mapping(raw);
        let (mut results, unanchored) = parse::anchor(text, raw)?;
        self.apply_confidence(&mut results);
        increment_by(metric_names::entities_detected(), results.len() as u64);
        if unanchored > 0 {
            increment_by(metric_names::spans_unanchored(), unanchored as u64);
        }

        if self.emit_events {
            observe::info(
                "llm.recognizer.analyze",
                format!(
                    "provider={} model={} latency_ms={:.1} prompt_tokens={} completion_tokens={} \
cache_read_tokens={} cache_hit={} finish_reason={:?} entities={} unanchored={} outcome=ok",
                    self.provider.name(),
                    response.model,
                    elapsed_ms,
                    usage.prompt_tokens,
                    usage.completion_tokens,
                    usage
                        .cache_read_tokens
                        .map_or_else(|| "n/a".to_string(), |n| n.to_string()),
                    usage.is_cache_hit(),
                    response.finish_reason,
                    results.len(),
                    unanchored,
                ),
            );
        }

        Ok(results)
    }

    fn name(&self) -> &str {
        self.name.as_deref().unwrap_or_else(|| self.provider.name())
    }

    fn supported_entities(&self) -> &[IdentifierType] {
        &self.supported
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::types::{FinishReason, LlmResponse, TokenUsage};
    use std::sync::Mutex;

    /// A provider returning a canned body, recording what it was asked.
    struct StubProvider {
        body: String,
        calls: Mutex<Vec<LlmRequest>>,
    }

    impl StubProvider {
        fn new(body: &str) -> Self {
            Self {
                body: body.to_string(),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().map_or(0, |c| c.len())
        }
    }

    #[async_trait]
    impl LlmProvider for StubProvider {
        async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(request.clone());
            }
            Ok(LlmResponse {
                content: self.body.clone(),
                finish_reason: FinishReason::Stop,
                usage: TokenUsage {
                    prompt_tokens: 100,
                    completion_tokens: 20,
                    cache_creation_tokens: None,
                    cache_read_tokens: Some(80),
                },
                model: "stub-model".to_string(),
            })
        }

        fn name(&self) -> &str {
            "stub"
        }
    }

    const ONE_EMAIL: &str =
        r#"{"entities":[{"type":"EMAIL_ADDRESS","text":"alice@example.com","score":0.95}]}"#;

    #[tokio::test]
    async fn detects_and_anchors_an_entity() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL)).silent();
        let text = "Reach alice@example.com today";
        let results = rec.analyze(text, "en", &[]).await.expect("detection ok");

        let first = results.first().expect("one result");
        assert_eq!(first.entity_type, "EMAIL_ADDRESS");
        assert_eq!(
            text.get(first.start..first.end),
            Some("alice@example.com"),
            "the span must cover the detected value in the ORIGINAL text"
        );
        assert_eq!(first.score, 0.95);
    }

    // ---- config-driven behaviour -------------------------------------------

    #[tokio::test]
    async fn a_configured_system_prompt_replaces_the_built_in_one() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_system_prompt("CUSTOM_PROMPT_MARKER")
            .silent();
        let _ = rec.analyze("Reach alice@example.com", "en", &[]).await;

        let calls = rec.provider.calls.lock().expect("lock");
        let sent = calls.first().expect("one call");
        assert_eq!(
            sent.system_prompt, "CUSTOM_PROMPT_MARKER",
            "the configured prompt must be sent verbatim, not appended to the default"
        );
    }

    #[tokio::test]
    async fn without_a_configured_prompt_the_built_in_one_is_used() {
        // Guards the default path: `with_system_prompt` is opt-in.
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL)).silent();
        let _ = rec.analyze("Reach alice@example.com", "en", &[]).await;

        let calls = rec.provider.calls.lock().expect("lock");
        let sent = calls.first().expect("one call");
        assert!(
            sent.system_prompt.contains("VERBATIM"),
            "the built-in detection prompt must still be used by default"
        );
    }

    #[tokio::test]
    async fn the_entity_mapping_rewrites_a_models_label() {
        let mut mapping = HashMap::new();
        mapping.insert("EMAIL_ADDRESS".to_string(), IdentifierType::Username);

        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_entity_mapping(mapping)
            .silent();
        let results = rec
            .analyze("Reach alice@example.com", "en", &[])
            .await
            .expect("detection ok");

        // Deliberately maps onto a DIFFERENT type than the model reported: a
        // mapping to the same label would pass even if mapping were a no-op.
        assert_eq!(
            results.first().map(|r| r.entity_type.as_str()),
            Some("USERNAME"),
            "the mapped type must replace the model's own label"
        );
    }

    #[tokio::test]
    async fn an_unmapped_label_passes_through_rather_than_being_dropped() {
        // The mapping narrows vocabulary; it is not an allow-list.
        let mut mapping = HashMap::new();
        mapping.insert("SOMETHING_ELSE".to_string(), IdentifierType::Username);

        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_entity_mapping(mapping)
            .silent();
        let results = rec
            .analyze("Reach alice@example.com", "en", &[])
            .await
            .expect("detection ok");

        assert_eq!(
            results.first().map(|r| r.entity_type.as_str()),
            Some("EMAIL_ADDRESS"),
            "an unmapped label must survive, not be filtered out"
        );
    }

    #[tokio::test]
    async fn a_constant_confidence_overrides_the_models_score() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_confidence(ConfidencePolicy::Constant(0.42))
            .silent();
        let results = rec
            .analyze("Reach alice@example.com", "en", &[])
            .await
            .expect("detection ok");

        // The stub reports 0.95, so 0.42 can only come from the policy.
        assert_eq!(
            results.first().map(|r| r.score),
            Some(0.42),
            "a constant policy must replace the model's reported score"
        );
    }

    #[tokio::test]
    async fn from_model_confidence_keeps_the_reported_score() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_confidence(ConfidencePolicy::FromModel)
            .silent();
        let results = rec
            .analyze("Reach alice@example.com", "en", &[])
            .await
            .expect("detection ok");

        assert_eq!(
            results.first().map(|r| r.score),
            Some(0.95),
            "from_model must leave the model's score untouched"
        );
    }

    #[tokio::test]
    async fn a_configured_name_replaces_the_provider_name() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL)).with_name("person_finder");
        assert_eq!(
            rec.name(),
            "person_finder",
            "two instances of one provider must stay distinguishable"
        );

        let unnamed = LLMRecognizer::new(StubProvider::new(ONE_EMAIL));
        assert_eq!(
            unnamed.name(),
            "stub",
            "without a configured name the provider name is still used"
        );
    }

    #[tokio::test]
    async fn empty_input_short_circuits_without_calling_the_provider() {
        let provider = StubProvider::new(ONE_EMAIL);
        let rec = LLMRecognizer::new(provider).silent();
        let results = rec.analyze("", "en", &[]).await.expect("ok");

        assert!(results.is_empty());
        assert_eq!(
            rec.provider.call_count(),
            0,
            "empty input must not be billed as a provider call"
        );
    }

    #[tokio::test]
    async fn narrowing_to_unsupported_types_skips_the_provider_call() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_supported_entities(vec![IdentifierType::Email])
            .silent();

        let results = rec
            .analyze("alice@example.com", "en", &[IdentifierType::CreditCard])
            .await
            .expect("ok");

        assert!(results.is_empty());
        assert_eq!(
            rec.provider.call_count(),
            0,
            "no supported type was requested, so there is nothing to ask"
        );
    }

    #[tokio::test]
    async fn empty_request_slice_still_calls_the_provider() {
        // The contract says empty means "everything" — the opposite of the
        // narrowing case above.
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_supported_entities(vec![IdentifierType::Email])
            .silent();

        let results = rec
            .analyze("Reach alice@example.com", "en", &[])
            .await
            .expect("ok");

        assert_eq!(rec.provider.call_count(), 1);
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn requested_types_are_narrowed_to_the_supported_intersection() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_supported_entities(vec![IdentifierType::Email, IdentifierType::Ssn])
            .silent();

        let _ = rec
            .analyze(
                "text",
                "en",
                &[IdentifierType::Email, IdentifierType::CreditCard],
            )
            .await
            .expect("ok");

        let calls = rec.provider.calls.lock().expect("lock");
        let sent = calls.first().expect("one call");
        assert!(
            sent.system_prompt.contains("Email"),
            "the supported+requested type must be asked for"
        );
        assert!(
            !sent.system_prompt.contains("CreditCard"),
            "an unsupported type must be dropped from the prompt"
        );
    }

    #[tokio::test]
    async fn hallucinated_entity_is_dropped_not_mispositioned() {
        let body = r#"{"entities":[
            {"type":"EMAIL_ADDRESS","text":"alice@example.com","score":0.95},
            {"type":"US_SSN","text":"123-45-6789","score":0.99}
        ]}"#;
        let rec = LLMRecognizer::new(StubProvider::new(body)).silent();
        let text = "Reach alice@example.com today";

        let results = rec.analyze(text, "en", &[]).await.expect("ok");

        assert_eq!(results.len(), 1, "the invented SSN must be dropped");
        assert_eq!(
            results.first().map(|r| r.entity_type.as_str()),
            Some("EMAIL_ADDRESS"),
            "the survivor must be the entity actually present in the text"
        );
    }

    #[tokio::test]
    async fn unparseable_response_errors_rather_than_reporting_no_pii() {
        let rec = LLMRecognizer::new(StubProvider::new("I cannot help with that.")).silent();
        let outcome = rec.analyze("Reach alice@example.com", "en", &[]).await;

        assert!(
            outcome.is_err(),
            "a failed parse must not be indistinguishable from a clean scan"
        );
    }

    #[tokio::test]
    async fn empty_detection_list_is_a_clean_empty_success() {
        let rec = LLMRecognizer::new(StubProvider::new(r#"{"entities":[]}"#)).silent();
        let results = rec.analyze("nothing to see", "en", &[]).await.expect("ok");
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn with_max_tokens_override_reaches_the_request() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_max_tokens(99)
            .silent();
        let _ = rec.analyze("text", "en", &[]).await.expect("ok");

        let calls = rec.provider.calls.lock().expect("lock");
        assert_eq!(
            calls.first().map(|r| r.max_tokens),
            Some(99),
            "the override must win over DEFAULT_MAX_TOKENS"
        );
    }

    #[tokio::test]
    async fn a_default_recognizer_is_not_skipped_by_a_registry_filter() {
        // `new()` advertises nothing, meaning everything. A registry using
        // `supports` must still route every entity type to it.
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL)).silent();

        assert!(rec.supported_entities().is_empty());
        assert!(
            rec.supports(&[IdentifierType::CreditCard]),
            "an all-purpose recognizer must not be filtered out"
        );
        assert!(rec.supports(&[]));
    }

    #[tokio::test]
    async fn a_narrowed_recognizer_is_skipped_for_disjoint_requests() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL))
            .with_supported_entities(vec![IdentifierType::Email])
            .silent();

        assert!(rec.supports(&[IdentifierType::Email]));
        assert!(!rec.supports(&[IdentifierType::CreditCard]));
    }

    #[tokio::test]
    async fn the_default_event_path_runs_without_panicking() {
        // Every other test calls `.silent()`, so the three observe:: branches
        // and their format strings would otherwise never execute.
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL));
        assert!(rec.emit_events, "events are on by default");

        let results = rec
            .analyze("Reach alice@example.com", "en", &[])
            .await
            .expect("detection succeeds");
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn the_default_event_path_runs_on_the_error_branch_too() {
        let rec = LLMRecognizer::new(StubProvider::new("not json at all"));
        let outcome = rec.analyze("Reach alice@example.com", "en", &[]).await;
        assert!(outcome.is_err(), "the parse-error event branch executes");
    }

    #[tokio::test]
    async fn name_reports_the_underlying_provider() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL)).silent();
        assert_eq!(rec.name(), "stub");
    }

    #[tokio::test]
    async fn detection_request_is_deterministic_and_cache_eligible() {
        let rec = LLMRecognizer::new(StubProvider::new(ONE_EMAIL)).silent();
        let _ = rec.analyze("text", "en", &[]).await.expect("ok");

        let calls = rec.provider.calls.lock().expect("lock");
        let sent = calls.first().expect("one call");
        assert_eq!(sent.temperature, 0.0, "detection must be deterministic");
        assert!(sent.cacheable, "the system prompt must be cache-eligible");
        assert_eq!(sent.max_tokens, DEFAULT_MAX_TOKENS);
    }
}
