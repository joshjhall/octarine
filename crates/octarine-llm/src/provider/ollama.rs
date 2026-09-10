//! Ollama client for locally-hosted models.
//!
//! Ollama's `/api/chat` is close to the OpenAI shape but not identical: options
//! like `temperature` live in an `options` object, structured output is
//! requested with `format: "json"` rather than a `response_format` object, and
//! token counts come back as `prompt_eval_count` / `eval_count`.
//!
//! There is no authentication — Ollama binds to localhost by default.

use async_trait::async_trait;
use octarine::runtime::http::HttpClient;
use octarine_problem::{Problem, Result};
use serde::{Deserialize, Serialize};

use super::{build_client, require_non_empty};
use crate::error::problem_for_status;
use crate::types::{FinishReason, LlmProvider, LlmRequest, LlmResponse, TokenUsage};

/// Default Ollama address.
const OLLAMA_BASE_URL: &str = "http://localhost:11434";

/// Chat endpoint, relative to the base URL.
const CHAT_PATH: &str = "/api/chat";

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// A message in an Ollama conversation.
///
/// No `Debug`: `content` is the text under analysis — the PII this crate
/// exists to find — and a derived impl would print it in full.
#[derive(Clone, Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

/// Generation options, which Ollama nests rather than flattening.
#[derive(Debug, Clone, Serialize)]
struct Options {
    temperature: f32,
    /// Ollama's spelling of `max_tokens`.
    num_predict: u32,
}

/// An Ollama chat request body.
///
/// No `Debug` — it transitively carries the analyzed text.
#[derive(Clone, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    /// Always `false` — [`LlmProvider::complete`] is the non-streaming path,
    /// and Ollama streams by default, which would otherwise return a sequence
    /// of NDJSON objects instead of one response.
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'static str>,
    options: Options,
}

impl<'a> ChatRequest<'a> {
    /// Renders an [`LlmRequest`] into Ollama's wire format.
    fn from_llm_request(request: &'a LlmRequest, model: &'a str) -> Self {
        Self {
            model,
            messages: vec![
                Message {
                    role: "system",
                    content: &request.system_prompt,
                },
                Message {
                    role: "user",
                    content: &request.user_prompt,
                },
            ],
            stream: false,
            format: request.json_mode.then_some("json"),
            options: Options {
                temperature: request.temperature,
                num_predict: request.max_tokens,
            },
        }
    }
}

/// An Ollama chat response body.
#[derive(Debug, Clone, Deserialize)]
struct ChatResponse {
    #[serde(default)]
    message: Option<ResponseMessage>,
    #[serde(default)]
    done_reason: Option<String>,
    #[serde(default)]
    prompt_eval_count: Option<u32>,
    #[serde(default)]
    eval_count: Option<u32>,
    #[serde(default)]
    model: Option<String>,
}

/// The assistant message.
#[derive(Debug, Clone, Deserialize)]
struct ResponseMessage {
    #[serde(default)]
    content: Option<String>,
}

impl ChatResponse {
    /// Converts into the vendor-neutral response.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Parse`] when the response carries no message content.
    fn into_llm_response(self, requested_model: &str) -> Result<LlmResponse> {
        let content = self
            .message
            .and_then(|m| m.content)
            .ok_or_else(|| Problem::Parse("response contained no message content".to_string()))?;

        let finish_reason = self
            .done_reason
            .as_deref()
            .map_or(FinishReason::Stop, FinishReason::from_provider_str);

        // Ollama has no prompt cache, so both cache fields stay None — an
        // honest "not reported" rather than a misleading zero.
        let usage = TokenUsage {
            prompt_tokens: self.prompt_eval_count.unwrap_or(0),
            completion_tokens: self.eval_count.unwrap_or(0),
            cache_creation_tokens: None,
            cache_read_tokens: None,
        };

        Ok(LlmResponse {
            content,
            finish_reason,
            usage,
            model: self.model.unwrap_or_else(|| requested_model.to_string()),
        })
    }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// A client for a local Ollama server.
#[derive(Debug, Clone)]
pub struct OllamaProvider {
    client: HttpClient,
    model: String,
}

impl OllamaProvider {
    /// Builds a provider against `http://localhost:11434`.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Config`] for an empty model.
    pub fn new(model: &str) -> Result<Self> {
        Self::with_base_url(model, OLLAMA_BASE_URL)
    }

    /// Builds a provider against a remote Ollama host.
    ///
    /// # Errors
    ///
    /// As [`OllamaProvider::new`].
    pub fn with_base_url(model: &str, base_url: &str) -> Result<Self> {
        let model = require_non_empty("model", model)?;
        let base_url = require_non_empty("base_url", base_url)?;
        Ok(Self {
            client: build_client("ollama", &base_url)?,
            model,
        })
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
        let body = ChatRequest::from_llm_request(request, &self.model);

        let response = self
            .client
            .post(CHAT_PATH)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(problem_for_status("ollama", status, &text));
        }

        let decoded: ChatResponse = response
            .json()
            .await
            .map_err(|e| Problem::Parse(format!("ollama response did not decode: {e}")))?;

        decoded.into_llm_response(&self.model)
    }

    fn name(&self) -> &str {
        "ollama"
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
    fn construction_rejects_an_empty_model_but_needs_no_credential() {
        assert!(OllamaProvider::new("").is_err());
        assert!(
            OllamaProvider::new("llama3").is_ok(),
            "a local server needs no API key"
        );
    }

    #[test]
    fn streaming_is_disabled_so_the_body_is_one_json_object() {
        // Ollama streams by default; leaving it on yields NDJSON that the
        // single-object decoder cannot parse.
        let llm = detection_request();
        let wire = ChatRequest::from_llm_request(&llm, "llama3");
        assert!(!wire.stream);
    }

    #[test]
    fn generation_options_are_nested_not_flattened() {
        let llm = detection_request();
        let json = serde_json::to_value(ChatRequest::from_llm_request(&llm, "llama3"))
            .expect("serializes");

        assert_eq!(
            json.get("options").and_then(|o| o.get("num_predict")),
            Some(&serde_json::json!(512)),
            "max_tokens must be sent as options.num_predict"
        );
        assert_eq!(
            json.get("options").and_then(|o| o.get("temperature")),
            Some(&serde_json::json!(0.0))
        );
        assert!(
            json.get("num_predict").is_none(),
            "options must not also be flattened onto the root"
        );
    }

    #[test]
    fn json_mode_uses_a_bare_format_string_not_an_object() {
        let llm = detection_request();
        let json =
            serde_json::to_value(ChatRequest::from_llm_request(&llm, "m")).expect("serializes");
        assert_eq!(
            json.get("format"),
            Some(&serde_json::json!("json")),
            "Ollama takes format: \"json\", not OpenAI's response_format object"
        );
    }

    #[test]
    fn json_mode_off_omits_the_format_field() {
        let mut llm = detection_request();
        llm.json_mode = false;
        let json =
            serde_json::to_string(&ChatRequest::from_llm_request(&llm, "m")).expect("serializes");
        assert!(!json.contains("format"));
    }

    #[test]
    fn response_maps_ollamas_own_token_count_names() {
        let body = r#"{
            "model": "llama3",
            "message": {"role": "assistant", "content": "{\"entities\":[]}"},
            "done_reason": "stop",
            "prompt_eval_count": 200,
            "eval_count": 15
        }"#;
        let decoded: ChatResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("llama3").expect("converts");

        assert_eq!(response.content, r#"{"entities":[]}"#);
        assert_eq!(
            response.usage.prompt_tokens, 200,
            "prompt_eval_count is the prompt token count"
        );
        assert_eq!(response.usage.completion_tokens, 15);
        assert_eq!(
            response.usage.cache_read_tokens, None,
            "Ollama has no prompt cache; None is honest, Some(0) would not be"
        );
    }

    #[test]
    fn absent_done_reason_defaults_to_stop() {
        // Ollama omits done_reason on a normal completion.
        let body = r#"{"message":{"content":"x"}}"#;
        let decoded: ChatResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("m").expect("converts");
        assert_eq!(response.finish_reason, FinishReason::Stop);
    }

    #[test]
    fn length_done_reason_is_reported_as_truncated() {
        let body = r#"{"message":{"content":"{"},"done_reason":"length"}"#;
        let decoded: ChatResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("m").expect("converts");
        assert!(response.finish_reason.is_truncated());
    }

    #[test]
    fn response_without_content_is_a_parse_error() {
        let decoded: ChatResponse =
            serde_json::from_str(r#"{"done_reason":"stop"}"#).expect("decodes");
        assert!(decoded.into_llm_response("m").is_err());
    }
}
