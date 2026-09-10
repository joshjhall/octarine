//! The five completion backends.
//!
//! Each provider owns its wire format and authentication. All of them share the
//! transport built by [`build_client`] — octarine's outbound
//! `octarine::runtime::http::HttpClient`, which already supplies connection
//! pooling, a circuit breaker, and retry-with-backoff driven by octarine's own
//! status classification (429 → long backoff, 408/425/5xx → standard backoff).
//! No provider implements a retry loop of its own.

pub mod anthropic;
pub mod azure_openai;
pub mod ollama;
pub mod openai;
pub mod openai_compatible;

pub use anthropic::AnthropicProvider;
pub use azure_openai::AzureOpenAiProvider;
pub use ollama::OllamaProvider;
pub use openai::OpenAiProvider;
pub use openai_compatible::OpenAiCompatibleProvider;

use octarine::runtime::http::{HttpClient, HttpClientConfig};
use octarine_problem::{Problem, Result};
use std::time::Duration;

/// Per-request timeout.
///
/// Generous compared to a normal API call: a large detection prompt against a
/// slow local model legitimately takes tens of seconds, and cutting it short
/// turns a working configuration into a flaky one.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Builds the shared transport for a provider.
///
/// Starts from the `for_external_api` preset — retries with exponential
/// backoff plus a circuit breaker — and widens the timeout for generation
/// latency.
///
/// # Errors
///
/// Returns [`Problem`] if the underlying client cannot be constructed.
pub fn build_client(name: &str, base_url: &str) -> Result<HttpClient> {
    let config = HttpClientConfig::builder()
        .base_url(base_url)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("octarine-llm/", env!("CARGO_PKG_VERSION")))
        .build();

    HttpClient::with_name(name.to_string(), config)
}

/// Rejects an empty credential before it reaches the network.
///
/// An empty key produces a 401 several seconds later, with a message about
/// authentication rather than about configuration. Failing at construction
/// points at the actual mistake.
///
/// # Errors
///
/// Returns [`Problem::Config`] when `value` is empty or whitespace.
pub(crate) fn require_non_empty(field: &str, value: &str) -> Result<String> {
    if value.trim().is_empty() {
        return Err(Problem::Config(format!("{field} must not be empty")));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn empty_credentials_are_rejected_at_construction() {
        assert!(require_non_empty("api_key", "").is_err());
        assert!(
            require_non_empty("api_key", "   ").is_err(),
            "whitespace is not a credential"
        );
    }

    #[test]
    fn valid_credentials_pass_through_unmodified() {
        let key = require_non_empty("api_key", "sk-abc123").expect("valid");
        assert_eq!(key, "sk-abc123");
    }

    #[test]
    fn rejection_names_the_offending_field() {
        let err = require_non_empty("deployment", "").expect_err("must reject");
        assert!(
            err.to_string().contains("deployment"),
            "the message must identify which field was empty"
        );
    }
}
