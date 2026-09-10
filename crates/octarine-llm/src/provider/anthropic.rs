//! Anthropic messages-API client, with prompt caching.
//!
//! Differs from the OpenAI family in three ways that matter here:
//!
//! - The system prompt is a **top-level field**, not a message with
//!   `role: "system"`.
//! - `max_tokens` is required, not optional.
//! - Prompt caching is **explicit**: a `cache_control` block marks the
//!   cache-eligible prefix. Without it there is no caching at all, unlike
//!   OpenAI's automatic behaviour.
//!
//! # Prompt caching
//!
//! The system prompt is sent as a content *block* (rather than a bare string)
//! so a `cache_control: {"type": "ephemeral"}` marker can be attached to it.
//! Because [`system_prompt`](crate::recognizer::prompt::system_prompt) is
//! byte-stable for a given entity set, every call after the first reads that
//! prefix from cache — reported back as `cache_read_input_tokens` and billed at
//! the cached tier.

use async_trait::async_trait;
use octarine::runtime::http::HttpClient;
use octarine_problem::{Problem, Result};
use serde::{Deserialize, Serialize};

use super::{Credential, build_client, require_non_empty};
use crate::error::problem_for_status;
use crate::types::{FinishReason, LlmProvider, LlmRequest, LlmResponse, TokenUsage};

/// Default API root.
const ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com/v1";

/// Messages endpoint, relative to the base URL.
const MESSAGES_PATH: &str = "/messages";

/// Wire version header value.
///
/// Pinned for the same reason as Azure's `api-version`: an unpinned version
/// lets an upstream change alter response shapes without a code change here.
const ANTHROPIC_VERSION: &str = "2023-06-01";

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// Cache directive attached to a content block.
#[derive(Debug, Clone, Serialize)]
struct CacheControl {
    #[serde(rename = "type")]
    control_type: &'static str,
}

impl CacheControl {
    /// The `ephemeral` cache tier — a short-lived prefix cache.
    fn ephemeral() -> Self {
        Self {
            control_type: "ephemeral",
        }
    }
}

/// A system-prompt content block, optionally cache-marked.
#[derive(Debug, Clone, Serialize)]
struct SystemBlock<'a> {
    #[serde(rename = "type")]
    block_type: &'static str,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<CacheControl>,
}

/// A user/assistant message.
#[derive(Debug, Clone, Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

/// An Anthropic messages request body.
#[derive(Debug, Clone, Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    temperature: f32,
    system: Vec<SystemBlock<'a>>,
    messages: Vec<Message<'a>>,
}

impl<'a> MessagesRequest<'a> {
    /// Renders an [`LlmRequest`] into Anthropic's wire format.
    fn from_llm_request(request: &'a LlmRequest, model: &'a str) -> Self {
        Self {
            model,
            max_tokens: request.max_tokens,
            temperature: request.temperature,
            system: vec![SystemBlock {
                block_type: "text",
                text: &request.system_prompt,
                cache_control: request.cacheable.then(CacheControl::ephemeral),
            }],
            messages: vec![Message {
                role: "user",
                content: &request.user_prompt,
            }],
        }
    }
}

/// An Anthropic messages response body.
#[derive(Debug, Clone, Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    content: Vec<ContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: Option<Usage>,
    #[serde(default)]
    model: Option<String>,
}

/// One block of response content.
#[derive(Debug, Clone, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type", default)]
    block_type: String,
    #[serde(default)]
    text: Option<String>,
}

/// Token accounting as Anthropic reports it.
#[derive(Debug, Clone, Copy, Deserialize)]
struct Usage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
    #[serde(default)]
    cache_creation_input_tokens: Option<u32>,
    #[serde(default)]
    cache_read_input_tokens: Option<u32>,
}

impl MessagesResponse {
    /// Converts into the vendor-neutral response.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Parse`] when no text block is present. Non-text
    /// blocks are skipped rather than treated as content — a `thinking` block
    /// is not the answer.
    fn into_llm_response(self, requested_model: &str) -> Result<LlmResponse> {
        let content = self
            .content
            .into_iter()
            .find(|b| b.block_type == "text")
            .and_then(|b| b.text)
            .ok_or_else(|| Problem::Parse("response contained no text block".to_string()))?;

        let finish_reason = self
            .stop_reason
            .as_deref()
            .map_or(FinishReason::Other, FinishReason::from_provider_str);

        let usage = self.usage.map_or_else(TokenUsage::default, |u| TokenUsage {
            prompt_tokens: u.input_tokens,
            completion_tokens: u.output_tokens,
            cache_creation_tokens: u.cache_creation_input_tokens,
            cache_read_tokens: u.cache_read_input_tokens,
        });

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

/// A client for Anthropic's messages API.
#[derive(Debug, Clone)]
pub struct AnthropicProvider {
    client: HttpClient,
    api_key: Credential,
    model: String,
}

impl AnthropicProvider {
    /// Builds a provider against `https://api.anthropic.com/v1`.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Config`] for an empty key or model.
    pub fn new(api_key: &str, model: &str) -> Result<Self> {
        Self::with_base_url(api_key, model, ANTHROPIC_BASE_URL)
    }

    /// Builds a provider against a custom base URL — a gateway or proxy that
    /// speaks the Anthropic API.
    ///
    /// # Errors
    ///
    /// As [`AnthropicProvider::new`].
    pub fn with_base_url(api_key: &str, model: &str, base_url: &str) -> Result<Self> {
        let api_key = require_non_empty("api_key", api_key)?;
        let model = require_non_empty("model", model)?;
        Ok(Self {
            client: build_client("anthropic", base_url)?,
            api_key: Credential::new(api_key),
            model,
        })
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
        let body = MessagesRequest::from_llm_request(request, &self.model);

        let response = self
            .client
            .post(MESSAGES_PATH)
            .header("x-api-key", self.api_key.expose().to_string())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(problem_for_status("anthropic", status, &text));
        }

        let decoded: MessagesResponse = response
            .json()
            .await
            .map_err(|e| Problem::Parse(format!("anthropic response did not decode: {e}")))?;

        decoded.into_llm_response(&self.model)
    }

    fn name(&self) -> &str {
        "anthropic"
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
        assert!(AnthropicProvider::new("", "claude-sonnet-5").is_err());
        assert!(AnthropicProvider::new("sk-ant-x", "").is_err());
        assert!(AnthropicProvider::new("sk-ant-x", "claude-sonnet-5").is_ok());
    }

    #[test]
    fn system_prompt_is_a_top_level_block_not_a_message() {
        // Sending it as a message would break caching AND change behaviour.
        let llm = detection_request();
        let wire = MessagesRequest::from_llm_request(&llm, "claude-sonnet-5");

        assert_eq!(wire.system.len(), 1);
        assert_eq!(wire.system.first().map(|b| b.text), Some("sys prompt"));
        assert_eq!(wire.messages.len(), 1, "only the user turn is a message");
        assert_eq!(wire.messages.first().map(|m| m.role), Some("user"));
    }

    #[test]
    fn cacheable_request_attaches_an_ephemeral_cache_control_block() {
        let llm = detection_request();
        let json =
            serde_json::to_value(MessagesRequest::from_llm_request(&llm, "m")).expect("serializes");

        let block = json
            .get("system")
            .and_then(|s| s.get(0))
            .expect("a system block");
        assert_eq!(
            block.get("cache_control").and_then(|c| c.get("type")),
            Some(&serde_json::json!("ephemeral")),
            "prompt caching requires an explicit ephemeral marker"
        );
        assert_eq!(block.get("type"), Some(&serde_json::json!("text")));
    }

    #[test]
    fn non_cacheable_request_omits_cache_control_entirely() {
        let mut llm = detection_request();
        llm.cacheable = false;
        let json = serde_json::to_string(&MessagesRequest::from_llm_request(&llm, "m"))
            .expect("serializes");

        assert!(
            !json.contains("cache_control"),
            "the marker must be absent, not serialized as null"
        );
    }

    #[test]
    fn response_surfaces_both_cache_creation_and_cache_read_tokens() {
        // The acceptance criterion: cache-eligible prompt drops to cached tier.
        let body = r#"{
            "model": "claude-sonnet-5",
            "content": [{"type": "text", "text": "{\"entities\":[]}"}],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 12,
                "output_tokens": 8,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 1024
            }
        }"#;
        let decoded: MessagesResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded
            .into_llm_response("claude-sonnet-5")
            .expect("converts");

        assert_eq!(response.usage.cache_read_tokens, Some(1024));
        assert_eq!(response.usage.cache_creation_tokens, Some(0));
        assert!(
            response.usage.is_cache_hit(),
            "1024 cached tokens must register as a hit"
        );
        assert_eq!(
            response.usage.prompt_tokens, 12,
            "only the uncached remainder is billed at full rate"
        );
    }

    #[test]
    fn first_call_reports_cache_creation_and_is_not_a_hit() {
        let body = r#"{
            "content": [{"type": "text", "text": "x"}],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 12,
                "output_tokens": 3,
                "cache_creation_input_tokens": 1024,
                "cache_read_input_tokens": 0
            }
        }"#;
        let decoded: MessagesResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("m").expect("converts");

        assert_eq!(response.usage.cache_creation_tokens, Some(1024));
        assert!(
            !response.usage.is_cache_hit(),
            "writing the cache is not reading it"
        );
    }

    #[test]
    fn end_turn_maps_to_stop_and_max_tokens_to_length() {
        let stop = r#"{"content":[{"type":"text","text":"x"}],"stop_reason":"end_turn"}"#;
        let decoded: MessagesResponse = serde_json::from_str(stop).expect("decodes");
        assert_eq!(
            decoded
                .into_llm_response("m")
                .expect("converts")
                .finish_reason,
            FinishReason::Stop
        );

        let truncated = r#"{"content":[{"type":"text","text":"{"}],"stop_reason":"max_tokens"}"#;
        let decoded: MessagesResponse = serde_json::from_str(truncated).expect("decodes");
        let response = decoded.into_llm_response("m").expect("converts");
        assert_eq!(response.finish_reason, FinishReason::Length);
        assert!(response.finish_reason.is_truncated());
    }

    #[test]
    fn non_text_blocks_are_skipped_in_favour_of_the_text_block() {
        // A thinking block first must not be mistaken for the answer.
        let body = r#"{
            "content": [
                {"type": "thinking", "thinking": "hmm"},
                {"type": "text", "text": "{\"entities\":[]}"}
            ],
            "stop_reason": "end_turn"
        }"#;
        let decoded: MessagesResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("m").expect("converts");
        assert_eq!(response.content, r#"{"entities":[]}"#);
    }

    #[test]
    fn response_without_a_text_block_is_a_parse_error() {
        let body = r#"{"content":[{"type":"thinking"}],"stop_reason":"end_turn"}"#;
        let decoded: MessagesResponse = serde_json::from_str(body).expect("decodes");
        assert!(
            decoded.into_llm_response("m").is_err(),
            "no text block must error, not silently yield empty content"
        );
    }

    #[test]
    fn absent_usage_leaves_cache_fields_unreported() {
        let body = r#"{"content":[{"type":"text","text":"x"}],"stop_reason":"end_turn"}"#;
        let decoded: MessagesResponse = serde_json::from_str(body).expect("decodes");
        let response = decoded.into_llm_response("m").expect("converts");

        assert_eq!(response.usage.cache_read_tokens, None);
        assert_eq!(response.usage.cache_creation_tokens, None);
    }
}
