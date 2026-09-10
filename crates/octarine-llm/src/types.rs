//! Provider-facing request/response types and the [`LlmProvider`] trait.
//!
//! These are the narrow waist between [`LLMRecognizer`](crate::LLMRecognizer)
//! and the five provider clients: the recognizer builds an [`LlmRequest`],
//! a provider turns it into a vendor-specific HTTP call, and the response comes
//! back as an [`LlmResponse`] regardless of which vendor produced it.

use async_trait::async_trait;
use octarine_problem::Result;
use serde::{Deserialize, Serialize};

/// A completion request, in vendor-neutral form.
///
/// Providers translate this into their own wire format — OpenAI's
/// `chat/completions` body, Anthropic's `messages` body, Ollama's `/api/chat`,
/// and so on.
// No `Eq`: `temperature` is an `f32`, which has no total equality.
// No derived `Debug` either — see the hand-written impl below.
#[derive(Clone, PartialEq)]
pub struct LlmRequest {
    /// The system prompt. Held separately from `user_prompt` because several
    /// providers place it in a distinct field, and because it is the portion
    /// eligible for prompt caching (see [`LlmRequest::cacheable`]).
    pub system_prompt: String,
    /// The user turn — in this crate, the text being analyzed.
    pub user_prompt: String,
    /// Model identifier, in the provider's own namespace
    /// (`"gpt-4o"`, `"claude-sonnet-5"`, `"llama3"`).
    pub model: String,
    /// Upper bound on generated tokens.
    pub max_tokens: u32,
    /// Sampling temperature. Detection wants determinism, so
    /// [`LlmRequest::for_detection`] pins this to `0.0`.
    pub temperature: f32,
    /// Request a structured-JSON response where the provider supports one.
    ///
    /// Not a guarantee: providers without a structured mode ignore this, which
    /// is why [`parse`](crate::recognizer::parse) always keeps a text fallback.
    pub json_mode: bool,
    /// Mark the system prompt as cache-eligible.
    ///
    /// Only Anthropic acts on this today, attaching a `cache_control` block to
    /// the system prompt. Other providers ignore it — either they cache
    /// automatically (OpenAI) or not at all.
    pub cacheable: bool,
}

impl LlmRequest {
    /// Builds a request configured for entity detection: deterministic
    /// (`temperature = 0.0`), structured output requested, system prompt marked
    /// cache-eligible.
    #[must_use]
    pub fn for_detection(
        system_prompt: impl Into<String>,
        user_prompt: impl Into<String>,
        model: impl Into<String>,
        max_tokens: u32,
    ) -> Self {
        Self {
            system_prompt: system_prompt.into(),
            user_prompt: user_prompt.into(),
            model: model.into(),
            max_tokens,
            temperature: 0.0,
            json_mode: true,
            cacheable: true,
        }
    }
}

impl std::fmt::Debug for LlmRequest {
    /// Elides both prompts, printing only their lengths.
    ///
    /// `user_prompt` is the text under analysis — by construction the PII this
    /// crate exists to find — and `system_prompt` can carry caller-supplied
    /// context. A derived `Debug` would print both in full from any `{:?}`,
    /// which is the same leak [`Credential`](crate::provider) prevents for API
    /// keys. Lengths are kept because they are useful for debugging a
    /// truncation and reveal nothing about the content.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmRequest")
            .field("model", &self.model)
            .field("system_prompt_len", &self.system_prompt.len())
            .field("user_prompt_len", &self.user_prompt.len())
            .field("max_tokens", &self.max_tokens)
            .field("temperature", &self.temperature)
            .field("json_mode", &self.json_mode)
            .field("cacheable", &self.cacheable)
            .finish()
    }
}

/// Why a provider stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// The model finished its turn normally.
    Stop,
    /// Generation hit the `max_tokens` ceiling — output is likely truncated,
    /// which for JSON output usually means an unparseable body.
    Length,
    /// The provider's content filter intervened.
    ContentFilter,
    /// The provider reported a reason this crate does not model.
    Other,
}

impl FinishReason {
    /// Maps a provider's raw finish-reason string onto the enum.
    ///
    /// Covers the OpenAI (`stop`/`length`/`content_filter`), Anthropic
    /// (`end_turn`/`max_tokens`/`stop_sequence`), and Ollama (`load`) spellings.
    /// An unrecognized value degrades to [`FinishReason::Other`] rather than
    /// erroring — a new upstream spelling should not fail a detection run.
    #[must_use]
    pub fn from_provider_str(raw: &str) -> Self {
        match raw {
            "stop" | "end_turn" | "stop_sequence" => Self::Stop,
            "length" | "max_tokens" => Self::Length,
            "content_filter" | "refusal" => Self::ContentFilter,
            _ => Self::Other,
        }
    }

    /// Whether the output was cut short, and so may be structurally incomplete.
    #[must_use]
    pub fn is_truncated(self) -> bool {
        matches!(self, Self::Length)
    }
}

/// Token accounting for one call.
///
/// The cache fields are `Option` rather than defaulting to `0` so that "this
/// provider does not report caching" stays distinguishable from "caching was
/// available and nothing was cached" — collapsing them would make a
/// misconfigured cache look like a working one reporting zero hits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Tokens in the prompt.
    pub prompt_tokens: u32,
    /// Tokens generated.
    pub completion_tokens: u32,
    /// Tokens written *into* the prompt cache on this call (Anthropic
    /// `cache_creation_input_tokens`). Billed at a premium.
    pub cache_creation_tokens: Option<u32>,
    /// Tokens served *from* the prompt cache (Anthropic
    /// `cache_read_input_tokens`). Billed at the cached tier — this is the
    /// number that should grow once caching is working.
    pub cache_read_tokens: Option<u32>,
}

impl TokenUsage {
    /// Total billed input+output tokens, ignoring cache tiering.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.prompt_tokens.saturating_add(self.completion_tokens)
    }

    /// Whether this call read anything from the prompt cache.
    #[must_use]
    pub fn is_cache_hit(&self) -> bool {
        self.cache_read_tokens.is_some_and(|n| n > 0)
    }
}

/// A completion response, in vendor-neutral form.
// No derived `Debug` — see the hand-written impl below.
#[derive(Clone, PartialEq, Eq)]
pub struct LlmResponse {
    /// The generated text — for detection, expected to hold a JSON document.
    pub content: String,
    /// Why generation stopped.
    pub finish_reason: FinishReason,
    /// Token accounting, when the provider reported it.
    pub usage: TokenUsage,
    /// The model that actually served the request, which may differ from the
    /// one requested (alias resolution, provider-side routing).
    pub model: String,
}

impl std::fmt::Debug for LlmResponse {
    /// Elides the generated content, printing only its length.
    ///
    /// The content is the model's detection output, which quotes the matched
    /// PII verbatim — printing it would leak exactly what was found.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmResponse")
            .field("model", &self.model)
            .field("content_len", &self.content.len())
            .field("finish_reason", &self.finish_reason)
            .field("usage", &self.usage)
            .finish()
    }
}

/// A vendor-specific completion backend.
///
/// One implementation per provider. Implementations own their wire format and
/// authentication, and are expected to compose on octarine's outbound
/// `HttpClient` for transport, retries, and circuit breaking rather than
/// driving `reqwest` directly.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Issues a single non-streaming completion.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Network`](octarine_problem::Problem::Network) for
    /// transport failures,
    /// [`Problem::Auth`](octarine_problem::Problem::Auth) for rejected
    /// credentials, and
    /// [`Problem::Parse`](octarine_problem::Problem::Parse) when the response
    /// body does not match the provider's documented shape.
    async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse>;

    /// Issues a completion over a streaming transport, reassembling the deltas
    /// into a complete response.
    ///
    /// Detection needs the whole JSON document before it can parse anything, so
    /// the return type is the same as [`complete`](LlmProvider::complete). What
    /// streaming buys is latency to first byte, bounded memory, and immunity to
    /// idle timeouts on a long generation.
    ///
    /// The default implementation delegates to
    /// [`complete`](LlmProvider::complete), so a provider without a streaming
    /// endpoint stays correct — callers always get a usable response.
    ///
    /// # Errors
    ///
    /// As [`complete`](LlmProvider::complete), plus
    /// [`Problem::Network`](octarine_problem::Problem::Network) if the stream
    /// breaks mid-flight.
    async fn complete_streaming(&self, request: &LlmRequest) -> Result<LlmResponse> {
        self.complete(request).await
    }

    /// A short, stable provider name (`"openai"`, `"anthropic"`), used as a
    /// metrics label and in event fields.
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn for_detection_pins_temperature_to_zero() {
        let req = LlmRequest::for_detection("sys", "user", "gpt-4o", 512);
        assert_eq!(
            req.temperature, 0.0,
            "detection must be deterministic, not merely low-temperature"
        );
        assert!(req.json_mode);
        assert!(req.cacheable);
    }

    #[test]
    fn request_debug_elides_the_analyzed_text() {
        // The user prompt IS the PII under analysis.
        let pii = "Reach alice@example.com, SSN 123-45-6789";
        let req = LlmRequest::for_detection("system rules here", pii, "gpt-4o", 512);
        let rendered = format!("{req:?}");

        assert!(
            !rendered.contains("alice@example.com"),
            "the analyzed text must not be printed, got: {rendered}"
        );
        assert!(!rendered.contains("123-45-6789"));
        assert!(!rendered.contains("system rules here"));
        assert!(
            rendered.contains("gpt-4o"),
            "non-sensitive fields stay visible for debugging"
        );
        assert!(
            rendered.contains(&pii.len().to_string()),
            "the length is kept — useful for debugging, reveals no content"
        );
    }

    #[test]
    fn response_debug_elides_the_detection_output() {
        // The content quotes the matched PII verbatim.
        let response = LlmResponse {
            content: r#"{"entities":[{"text":"alice@example.com"}]}"#.to_string(),
            finish_reason: FinishReason::Stop,
            usage: TokenUsage::default(),
            model: "gpt-4o".to_string(),
        };
        let rendered = format!("{response:?}");

        assert!(
            !rendered.contains("alice@example.com"),
            "detection output quotes the PII and must not be printed, got: {rendered}"
        );
        assert!(rendered.contains("gpt-4o"));
        assert!(rendered.contains("Stop"));
    }

    #[test]
    fn finish_reason_maps_each_vendor_spelling_to_its_own_variant() {
        // Anthropic and OpenAI spell the same two concepts differently; a
        // mapping that collapsed them would pass a weaker assertion.
        assert_eq!(FinishReason::from_provider_str("stop"), FinishReason::Stop);
        assert_eq!(
            FinishReason::from_provider_str("end_turn"),
            FinishReason::Stop
        );
        assert_eq!(
            FinishReason::from_provider_str("length"),
            FinishReason::Length
        );
        assert_eq!(
            FinishReason::from_provider_str("max_tokens"),
            FinishReason::Length,
            "Anthropic's max_tokens is a truncation, not a normal stop"
        );
        assert_eq!(
            FinishReason::from_provider_str("content_filter"),
            FinishReason::ContentFilter
        );
    }

    #[test]
    fn unknown_finish_reason_degrades_to_other_rather_than_stop() {
        // Degrading to Stop would silently claim a clean finish.
        assert_eq!(
            FinishReason::from_provider_str("brand_new_reason"),
            FinishReason::Other
        );
        assert_eq!(FinishReason::from_provider_str(""), FinishReason::Other);
    }

    #[test]
    fn only_length_counts_as_truncated() {
        assert!(FinishReason::Length.is_truncated());
        assert!(!FinishReason::Stop.is_truncated());
        assert!(!FinishReason::ContentFilter.is_truncated());
        assert!(!FinishReason::Other.is_truncated());
    }

    #[test]
    fn cache_hit_distinguishes_unreported_from_zero() {
        let unreported = TokenUsage {
            prompt_tokens: 10,
            completion_tokens: 5,
            cache_creation_tokens: None,
            cache_read_tokens: None,
        };
        let reported_zero = TokenUsage {
            cache_read_tokens: Some(0),
            ..unreported
        };
        let reported_hit = TokenUsage {
            cache_read_tokens: Some(900),
            ..unreported
        };

        assert!(!unreported.is_cache_hit(), "no report is not a hit");
        assert!(
            !reported_zero.is_cache_hit(),
            "a reported zero is not a hit"
        );
        assert!(reported_hit.is_cache_hit());
        // The distinction the Option preserves:
        assert_ne!(
            unreported.cache_read_tokens,
            reported_zero.cache_read_tokens
        );
    }

    #[test]
    fn total_saturates_rather_than_overflowing() {
        let usage = TokenUsage {
            prompt_tokens: u32::MAX,
            completion_tokens: 10,
            cache_creation_tokens: None,
            cache_read_tokens: None,
        };
        assert_eq!(usage.total(), u32::MAX);
    }
}
