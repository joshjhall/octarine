//! Generic OpenAI-compatible client.
//!
//! Covers every endpoint that speaks the OpenAI chat-completions wire format at
//! a different address: vLLM, LM Studio, Together, Groq, OpenRouter, Mistral,
//! Perplexity, and DeepInfra. Only the base URL and the API key differ, so this
//! reuses [`openai`](super::openai)'s request and response types wholesale.
//!
//! # Why a separate type rather than `OpenAiProvider::with_base_url`
//!
//! Two reasons, both operational. The `name()` is configurable, so metrics and
//! events attribute a call to `"groq"` rather than to `"openai"`; and a
//! self-hosted endpoint may legitimately have **no** API key, which the genuine
//! OpenAI provider correctly rejects.

use async_trait::async_trait;
use octarine::runtime::http::HttpClient;
use octarine_problem::Result;

use super::openai::{CHAT_COMPLETIONS_PATH, post_chat_completion, stream_chat_completion};
use super::{build_client, require_non_empty};
use crate::types::{LlmProvider, LlmRequest, LlmResponse};

/// A client for any OpenAI-compatible chat-completions endpoint.
#[derive(Debug, Clone)]
pub struct OpenAiCompatibleProvider {
    client: HttpClient,
    /// `None` for an unauthenticated local endpoint.
    api_key: Option<String>,
    model: String,
    name: String,
}

impl OpenAiCompatibleProvider {
    /// Builds a provider against `base_url` with bearer authentication.
    ///
    /// `name` labels the backend in metrics and events — use the vendor's name
    /// (`"groq"`, `"together"`) rather than `"openai-compatible"`, so a
    /// per-provider error rate is attributable.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Config`](octarine_problem::Problem::Config) if
    /// `name`, `base_url`, `model`, or `api_key` is empty.
    pub fn new(name: &str, base_url: &str, api_key: &str, model: &str) -> Result<Self> {
        let api_key = require_non_empty("api_key", api_key)?;
        Self::build(name, base_url, Some(api_key), model)
    }

    /// Builds a provider against an endpoint that requires no credential —
    /// a local vLLM or LM Studio server.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Config`](octarine_problem::Problem::Config) if
    /// `name`, `base_url`, or `model` is empty.
    pub fn without_auth(name: &str, base_url: &str, model: &str) -> Result<Self> {
        Self::build(name, base_url, None, model)
    }

    /// Shared construction path for both authenticated and open endpoints.
    fn build(name: &str, base_url: &str, api_key: Option<String>, model: &str) -> Result<Self> {
        let name = require_non_empty("name", name)?;
        let base_url = require_non_empty("base_url", base_url)?;
        let model = require_non_empty("model", model)?;
        Ok(Self {
            client: build_client(&name, &base_url)?,
            api_key,
            model,
            name,
        })
    }

    /// The `Authorization` value for this endpoint.
    ///
    /// An unauthenticated endpoint still needs a header slot; an empty value is
    /// harmless and keeps a single request path for both cases.
    fn auth_value(&self) -> String {
        self.api_key
            .as_ref()
            .map_or_else(String::new, |key| format!("Bearer {key}"))
    }
}

#[async_trait]
impl LlmProvider for OpenAiCompatibleProvider {
    async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
        post_chat_completion(
            &self.client,
            &self.name,
            CHAT_COMPLETIONS_PATH,
            ("Authorization", self.auth_value()),
            request,
            &self.model,
        )
        .await
    }

    async fn complete_streaming(&self, request: &LlmRequest) -> Result<LlmResponse> {
        stream_chat_completion(
            &self.client,
            &self.name,
            CHAT_COMPLETIONS_PATH,
            ("Authorization", self.auth_value()),
            request,
            &self.model,
        )
        .await
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn reports_the_configured_vendor_name_not_a_generic_label() {
        // Metrics attribution depends on this.
        let provider = OpenAiCompatibleProvider::new(
            "groq",
            "https://api.groq.com/openai/v1",
            "gsk-x",
            "llama-3.3-70b",
        )
        .expect("valid");
        assert_eq!(provider.name(), "groq");
    }

    #[test]
    fn authenticated_construction_requires_every_field() {
        assert!(OpenAiCompatibleProvider::new("", "https://x", "k", "m").is_err());
        assert!(OpenAiCompatibleProvider::new("n", "", "k", "m").is_err());
        assert!(
            OpenAiCompatibleProvider::new("n", "https://x", "", "m").is_err(),
            "the authenticated constructor must reject an empty key"
        );
        assert!(OpenAiCompatibleProvider::new("n", "https://x", "k", "").is_err());
    }

    #[test]
    fn without_auth_permits_a_missing_key_but_still_requires_the_rest() {
        let provider =
            OpenAiCompatibleProvider::without_auth("vllm", "http://localhost:8000/v1", "llama3")
                .expect("a local endpoint needs no key");
        assert!(provider.api_key.is_none());

        assert!(OpenAiCompatibleProvider::without_auth("vllm", "http://x", "").is_err());
        assert!(OpenAiCompatibleProvider::without_auth("", "http://x", "m").is_err());
    }
}
