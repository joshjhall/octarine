//! OpenAI chat-completions client, and the wire format shared with the
//! OpenAI-compatible and Azure OpenAI providers.
//!
//! The request/response shapes here are reused by
//! [`openai_compatible`](super::openai_compatible) and
//! [`azure_openai`](super::azure_openai), which differ only in URL construction
//! and authentication. Keeping one set of structs means a fix to response
//! handling lands for all three.
//!
//! # Chat Completions only
//!
//! This targets `/chat/completions`, not OpenAI's newer Responses API
//! (`/v1/responses`). Issue #520 named both; only chat-completions is
//! implemented, deliberately.
//!
//! Chat Completions is the format the other four providers already speak, so
//! one set of wire structs serves three of the five clients. The Responses API
//! is OpenAI-only — adding it would buy a second code path used by exactly one
//! provider, with no benefit for detection, which needs a single JSON document
//! back and nothing the newer API uniquely offers. Revisit if a needed feature
//! becomes Responses-only.

use async_trait::async_trait;
use octarine::runtime::http::HttpClient;
use octarine_problem::{Problem, Result};
use serde::{Deserialize, Serialize};

use super::{Credential, build_client, require_non_empty};
use crate::error::problem_for_status;
use crate::types::{FinishReason, LlmProvider, LlmRequest, LlmResponse, TokenUsage};

/// Default API root.
const OPENAI_BASE_URL: &str = "https://api.openai.com/v1";

/// Chat-completions path, relative to the base URL.
pub(crate) const CHAT_COMPLETIONS_PATH: &str = "/chat/completions";

// ---------------------------------------------------------------------------
// Wire format (shared)
// ---------------------------------------------------------------------------

/// One message in an OpenAI-format conversation.
///
/// No `Debug`: `content` is the text under analysis, which is by construction
/// the PII this crate exists to find. A derived `Debug` would print it in full
/// from any `{:?}` — the same leak `Credential` prevents for API keys.
#[derive(Clone, Serialize)]
pub(crate) struct ChatMessage<'a> {
    pub(crate) role: &'a str,
    pub(crate) content: &'a str,
}

/// An OpenAI-format chat-completions request body.
///
/// No `Debug` — it transitively carries the analyzed text via `messages`.
#[derive(Clone, Serialize)]
pub(crate) struct ChatRequest<'a> {
    pub(crate) model: &'a str,
    pub(crate) messages: Vec<ChatMessage<'a>>,
    pub(crate) max_completion_tokens: u32,
    pub(crate) temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_format: Option<ResponseFormat>,
}

/// Structured-output selector.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ResponseFormat {
    #[serde(rename = "type")]
    pub(crate) format_type: &'static str,
}

impl ResponseFormat {
    /// The `json_object` mode, which constrains output to a JSON document.
    pub(crate) fn json_object() -> Self {
        Self {
            format_type: "json_object",
        }
    }
}

impl<'a> ChatRequest<'a> {
    /// Renders an [`LlmRequest`] into the OpenAI wire format, using `model`
    /// (the provider's configured model) rather than the request's own field.
    pub(crate) fn from_llm_request(request: &'a LlmRequest, model: &'a str) -> Self {
        Self {
            model,
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: &request.system_prompt,
                },
                ChatMessage {
                    role: "user",
                    content: &request.user_prompt,
                },
            ],
            max_completion_tokens: request.max_tokens,
            temperature: request.temperature,
            response_format: request.json_mode.then(ResponseFormat::json_object),
        }
    }
}

/// An OpenAI-format response body.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ChatResponse {
    #[serde(default)]
    pub(crate) choices: Vec<ChatChoice>,
    #[serde(default)]
    pub(crate) usage: Option<ChatUsage>,
    #[serde(default)]
    pub(crate) model: Option<String>,
}

/// One completion choice.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ChatChoice {
    #[serde(default)]
    pub(crate) message: Option<ChatResponseMessage>,
    #[serde(default)]
    pub(crate) finish_reason: Option<String>,
}

/// The assistant message within a choice.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ChatResponseMessage {
    #[serde(default)]
    pub(crate) content: Option<String>,
}

/// Token accounting as OpenAI reports it.
#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) struct ChatUsage {
    #[serde(default)]
    pub(crate) prompt_tokens: u32,
    #[serde(default)]
    pub(crate) completion_tokens: u32,
    #[serde(default)]
    pub(crate) prompt_tokens_details: Option<PromptTokensDetails>,
}

/// The cached-token breakdown OpenAI reports for automatic prompt caching.
#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) struct PromptTokensDetails {
    #[serde(default)]
    pub(crate) cached_tokens: u32,
}

impl ChatResponse {
    /// Converts an OpenAI-format response into the vendor-neutral form.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Parse`] when the response carries no choice or no
    /// message content — an empty `choices` array is a malformed response, not
    /// an empty detection result, and must not be mistaken for one.
    pub(crate) fn into_llm_response(self, requested_model: &str) -> Result<LlmResponse> {
        let choice = self
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| Problem::Parse("response contained no choices".to_string()))?;

        let content = choice
            .message
            .and_then(|m| m.content)
            .ok_or_else(|| Problem::Parse("response choice contained no content".to_string()))?;

        let finish_reason = choice
            .finish_reason
            .as_deref()
            .map_or(FinishReason::Other, FinishReason::from_provider_str);

        let usage = self.usage.map_or_else(TokenUsage::default, |u| TokenUsage {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            cache_creation_tokens: None,
            cache_read_tokens: u.prompt_tokens_details.map(|d| d.cached_tokens),
        });

        Ok(LlmResponse {
            content,
            finish_reason,
            usage,
            model: self.model.unwrap_or_else(|| requested_model.to_string()),
        })
    }
}

/// Issues an OpenAI-format request and decodes the response.
///
/// Shared by all three OpenAI-shaped providers. `auth` supplies the
/// provider-specific credential header as `(name, value)`.
///
/// # Errors
///
/// Returns the [`Problem`] mapped by [`problem_for_status`] for a non-2xx
/// response, or [`Problem::Parse`] for a body that does not decode.
pub(crate) async fn post_chat_completion(
    client: &HttpClient,
    provider: &str,
    path: &str,
    auth: (&str, String),
    request: &LlmRequest,
    model: &str,
) -> Result<LlmResponse> {
    let body = ChatRequest::from_llm_request(request, model);
    let (auth_header, auth_value) = auth;

    let response = client
        .post(path)
        .header(auth_header, auth_value)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    let status = response.status().as_u16();
    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(problem_for_status(provider, status, &text));
    }

    let decoded: ChatResponse = response
        .json()
        .await
        .map_err(|e| super::decode_problem(provider, &e))?;

    decoded.into_llm_response(model)
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

/// One streamed chunk of an OpenAI-format completion.
#[derive(Debug, Clone, Deserialize)]
struct ChatChunk {
    #[serde(default)]
    choices: Vec<ChunkChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
    #[serde(default)]
    model: Option<String>,
}

/// A choice within a streamed chunk.
#[derive(Debug, Clone, Deserialize)]
struct ChunkChoice {
    #[serde(default)]
    delta: Option<ChunkDelta>,
    #[serde(default)]
    finish_reason: Option<String>,
}

/// The incremental content carried by a chunk.
#[derive(Debug, Clone, Deserialize)]
struct ChunkDelta {
    #[serde(default)]
    content: Option<String>,
}

/// Issues a streaming OpenAI-format request, accumulating deltas into a
/// complete response.
///
/// The detection pipeline needs the whole JSON document before it can parse
/// anything, so this reassembles rather than yielding partial results. The
/// value of streaming here is **latency to first byte and bounded memory** —
/// chunks are decoded and folded as they arrive rather than the whole body
/// being buffered by the transport — plus keeping long generations from
/// tripping an idle timeout.
///
/// # Errors
///
/// Returns the [`Problem`] mapped by [`problem_for_status`] for a non-2xx
/// response, [`Problem::Network`] if the stream breaks mid-flight, or
/// [`Problem::Parse`] if no content arrived.
pub(crate) async fn stream_chat_completion(
    client: &HttpClient,
    provider: &str,
    path: &str,
    auth: (&str, String),
    request: &LlmRequest,
    model: &str,
) -> Result<LlmResponse> {
    use futures_util::StreamExt;

    let mut body = serde_json::to_value(ChatRequest::from_llm_request(request, model))
        .map_err(|e| Problem::Parse(format!("could not build {provider} request: {e}")))?;
    if let Some(map) = body.as_object_mut() {
        map.insert("stream".to_string(), serde_json::Value::Bool(true));
        // Without `stream_options.include_usage`, OpenAI and Azure omit `usage`
        // from every streamed chunk — the accumulator below would then report
        // zero tokens for every streaming call while looking like it worked.
        map.insert(
            "stream_options".to_string(),
            serde_json::json!({"include_usage": true}),
        );
    }

    let (auth_header, auth_value) = auth;
    let response = client
        .post(path)
        .header(auth_header, auth_value)
        .header("Content-Type", "application/json")
        .header("Accept", "text/event-stream")
        .json(&body)
        .send()
        .await?;

    let status = response.status().as_u16();
    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(problem_for_status(provider, status, &text));
    }

    let mut decoder = crate::sse::SseDecoder::new();
    let mut content = String::new();
    let mut finish_reason = FinishReason::Other;
    let mut usage = TokenUsage::default();
    let mut served_model: Option<String> = None;

    let mut stream = response.into_inner().bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| Problem::Network(format!("{provider} stream failed mid-flight: {e}")))?;
        for event in decoder.push(&chunk) {
            fold_chunk(
                &event.data,
                &mut content,
                &mut finish_reason,
                &mut usage,
                &mut served_model,
            );
        }
        if decoder.is_overflowed() {
            return Err(Problem::Network(format!(
                "{provider} sent an SSE line exceeding the buffer limit; \
stream abandoned"
            )));
        }
        if decoder.is_done() {
            break;
        }
    }
    // A stream cut short of its terminating blank line still carries a usable
    // final event.
    if let Some(event) = decoder.finish() {
        fold_chunk(
            &event.data,
            &mut content,
            &mut finish_reason,
            &mut usage,
            &mut served_model,
        );
    }

    if content.is_empty() {
        return Err(Problem::Parse(format!(
            "{provider} stream produced no content"
        )));
    }

    Ok(LlmResponse {
        content,
        finish_reason,
        usage,
        model: served_model.unwrap_or_else(|| model.to_string()),
    })
}

/// Folds one SSE payload into the accumulating response.
///
/// A chunk that does not decode is **skipped rather than fatal**: providers
/// interleave keep-alives and occasional non-delta frames, and failing the
/// whole generation over one unrecognized frame would discard everything
/// already received.
fn fold_chunk(
    data: &str,
    content: &mut String,
    finish_reason: &mut FinishReason,
    usage: &mut TokenUsage,
    served_model: &mut Option<String>,
) {
    let Ok(chunk) = serde_json::from_str::<ChatChunk>(data) else {
        return;
    };
    if let Some(model) = chunk.model {
        *served_model = Some(model);
    }
    if let Some(u) = chunk.usage {
        *usage = TokenUsage {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            cache_creation_tokens: None,
            cache_read_tokens: u.prompt_tokens_details.map(|d| d.cached_tokens),
        };
    }
    for choice in chunk.choices {
        if let Some(delta) = choice.delta.and_then(|d| d.content) {
            content.push_str(&delta);
        }
        if let Some(raw) = choice.finish_reason {
            *finish_reason = FinishReason::from_provider_str(&raw);
        }
    }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// A client for OpenAI's chat-completions API.
#[derive(Debug, Clone)]
pub struct OpenAiProvider {
    client: HttpClient,
    api_key: Credential,
    model: String,
}

impl OpenAiProvider {
    /// Builds a provider against `https://api.openai.com/v1`.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Config`] for an empty key or model, or a transport
    /// error if the client cannot be constructed.
    pub fn new(api_key: &str, model: &str) -> Result<Self> {
        Self::with_base_url(api_key, model, OPENAI_BASE_URL)
    }

    /// Builds a provider against a custom base URL — for a proxy or gateway
    /// that still speaks the genuine OpenAI API.
    ///
    /// # Errors
    ///
    /// As [`OpenAiProvider::new`].
    pub fn with_base_url(api_key: &str, model: &str, base_url: &str) -> Result<Self> {
        let api_key = require_non_empty("api_key", api_key)?;
        let model = require_non_empty("model", model)?;
        Ok(Self {
            client: build_client("openai", base_url)?,
            api_key: Credential::new(api_key),
            model,
        })
    }
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
        post_chat_completion(
            &self.client,
            "openai",
            CHAT_COMPLETIONS_PATH,
            ("Authorization", format!("Bearer {}", self.api_key.expose())),
            request,
            &self.model,
        )
        .await
    }

    async fn complete_streaming(&self, request: &LlmRequest) -> Result<LlmResponse> {
        stream_chat_completion(
            &self.client,
            "openai",
            CHAT_COMPLETIONS_PATH,
            ("Authorization", format!("Bearer {}", self.api_key.expose())),
            request,
            &self.model,
        )
        .await
    }

    fn name(&self) -> &str {
        "openai"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn detection_request() -> LlmRequest {
        LlmRequest::for_detection("sys prompt", "user prompt", String::new(), 512)
    }

    #[test]
    fn construction_rejects_empty_key_and_model() {
        assert!(OpenAiProvider::new("", "gpt-4o").is_err());
        assert!(OpenAiProvider::new("sk-abc", "").is_err());
        assert!(OpenAiProvider::new("sk-abc", "gpt-4o").is_ok());
    }

    #[test]
    fn formatting_the_whole_provider_does_not_print_the_api_key() {
        // Credential's own Debug is unit-tested; this asserts the property
        // end-to-end, so a future hand-written Debug on the provider that
        // bypassed the newtype would be caught here.
        let secret = "sk-super-secret-value-12345";
        let provider = OpenAiProvider::new(secret, "gpt-4o").expect("valid");
        let rendered = format!("{provider:?}");

        // Assertion messages deliberately omit `rendered`. If the property
        // under test were violated, printing it on failure would put the very
        // credential into CI output — and a message that interpolates a
        // secret-derived string is a cleartext-logging sink to a static
        // analyzer regardless of whether the test passes.
        assert!(
            !rendered.contains(secret),
            "the provider must not print its credential"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(
            rendered.contains("gpt-4o"),
            "non-secret fields should still be visible for debugging"
        );
    }

    #[test]
    fn request_uses_the_configured_model_not_the_request_field() {
        // LlmRequest::model is left empty by the recognizer; the provider's
        // configured model is authoritative.
        let llm = detection_request();
        let wire = ChatRequest::from_llm_request(&llm, "gpt-4o");
        assert_eq!(wire.model, "gpt-4o");
    }

    #[test]
    fn request_places_system_and_user_prompts_in_order() {
        let llm = detection_request();
        let wire = ChatRequest::from_llm_request(&llm, "gpt-4o");

        assert_eq!(wire.messages.len(), 2);
        assert_eq!(wire.messages.first().map(|m| m.role), Some("system"));
        assert_eq!(wire.messages.first().map(|m| m.content), Some("sys prompt"));
        assert_eq!(wire.messages.get(1).map(|m| m.role), Some("user"));
    }

    #[test]
    fn json_mode_sets_response_format_and_off_omits_it() {
        let mut llm = detection_request();
        let with_json = ChatRequest::from_llm_request(&llm, "m");
        assert!(
            with_json.response_format.is_some(),
            "json_mode must request structured output"
        );

        llm.json_mode = false;
        let without = ChatRequest::from_llm_request(&llm, "m");
        assert!(
            without.response_format.is_none(),
            "the field must be omitted, not sent as null"
        );
    }

    #[test]
    fn serialized_body_omits_response_format_when_disabled() {
        let mut llm = detection_request();
        llm.json_mode = false;
        let json =
            serde_json::to_string(&ChatRequest::from_llm_request(&llm, "m")).expect("serializes");
        assert!(
            !json.contains("response_format"),
            "a None response_format must not appear in the body at all"
        );
    }

    #[test]
    fn response_decodes_content_usage_and_cached_tokens() {
        let body = r#"{
            "model": "gpt-4o-2024-11-20",
            "choices": [{"message": {"content": "{\"entities\":[]}"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 120,
                "completion_tokens": 8,
                "prompt_tokens_details": {"cached_tokens": 96}
            }
        }"#;
        let decoded: ChatResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("gpt-4o").expect("converts");

        assert_eq!(response.content, r#"{"entities":[]}"#);
        assert_eq!(response.finish_reason, FinishReason::Stop);
        assert_eq!(response.usage.prompt_tokens, 120);
        assert_eq!(response.usage.completion_tokens, 8);
        assert_eq!(
            response.usage.cache_read_tokens,
            Some(96),
            "OpenAI's cached_tokens must surface as cache_read_tokens"
        );
        assert_eq!(
            response.model, "gpt-4o-2024-11-20",
            "the serving model must win over the requested one"
        );
    }

    #[test]
    fn missing_usage_details_leave_cache_unreported_not_zero() {
        let body = r#"{
            "choices": [{"message": {"content": "x"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2}
        }"#;
        let decoded: ChatResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("m").expect("converts");

        assert_eq!(
            response.usage.cache_read_tokens, None,
            "absent details must stay None so 'unreported' != 'zero cached'"
        );
    }

    #[test]
    fn empty_choices_is_a_parse_error_not_an_empty_completion() {
        // Returning empty content here would be read downstream as "no PII".
        let decoded: ChatResponse = serde_json::from_str(r#"{"choices": []}"#).expect("decodes");
        assert!(decoded.into_llm_response("m").is_err());
    }

    #[test]
    fn choice_without_content_is_a_parse_error() {
        let decoded: ChatResponse =
            serde_json::from_str(r#"{"choices":[{"finish_reason":"stop"}]}"#).expect("decodes");
        assert!(decoded.into_llm_response("m").is_err());
    }

    #[test]
    fn length_finish_reason_is_preserved_as_truncated() {
        let body = r#"{"choices":[{"message":{"content":"{"},"finish_reason":"length"}]}"#;
        let decoded: ChatResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("m").expect("converts");

        assert_eq!(response.finish_reason, FinishReason::Length);
        assert!(
            response.finish_reason.is_truncated(),
            "truncation must stay visible so a parse failure is explicable"
        );
    }

    #[test]
    fn absent_model_falls_back_to_the_requested_one() {
        let body = r#"{"choices":[{"message":{"content":"x"},"finish_reason":"stop"}]}"#;
        let decoded: ChatResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("gpt-4o").expect("converts");
        assert_eq!(response.model, "gpt-4o");
    }
}
