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

/// A credential that never appears in `Debug` output.
///
/// Every provider holds an API key or bearer token, and every provider derives
/// `Debug` for ordinary ergonomics. A raw `String` field would then be printed
/// in full by any `{:?}` — a future log line, a `dbg!`, an error type that
/// embeds the provider, or a test assertion printing the struct on failure.
/// That is a credential leak into CI logs, and it is exactly the failure mode
/// `crypto::secrets` already guards against by hashing keys before logging.
///
/// Wrapping the credential makes the redaction structural rather than a rule
/// each provider has to remember: there is no way to derive `Debug` on a
/// provider and still print the secret.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credential(String);

impl Credential {
    /// Wraps a credential value.
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrows the raw value, for building an outbound header.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Credential {
    /// Prints a fixed placeholder — never the value, and never a length or
    /// prefix, both of which leak information about the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Describes a response-decode failure without quoting the body.
///
/// `reqwest::Error`'s own `Display` prints only the URL, but its **source**
/// is the underlying `serde_json::Error`, whose `Display` quotes the offending
/// value in full — `invalid type: string "...", expected a sequence`. For this
/// crate that value is model output about the text under analysis, so it is
/// the PII detection is meant to find.
///
/// Nothing prints that source today, which is exactly why this is worth
/// pinning: a later `{e:?}`, an `anyhow` chain, or any source-walking logger
/// would surface it silently. The reachable path is a provider refusing on
/// content policy with **HTTP 200** and a wrong-typed body — `problem_for_status`
/// never runs on a success status, and `analyze` logs the resulting `Problem`.
///
/// Reports the serde position and category, the same treatment
/// [`parse_entities`](crate::recognizer::parse::parse_entities) applies.
pub(crate) fn decode_problem(provider: &str, err: &reqwest::Error) -> Problem {
    use std::error::Error as _;

    let detail = err
        .source()
        .and_then(|s| s.downcast_ref::<serde_json::Error>())
        .map_or_else(
            || "malformed body".to_string(),
            |e| {
                format!(
                    "{:?} at line {}, column {}",
                    e.classify(),
                    e.line(),
                    e.column()
                )
            },
        );
    Problem::Parse(format!("{provider} response did not decode ({detail})"))
}

/// Rejects a value that would alter the URL it is interpolated into.
///
/// Azure addresses a model by splicing the deployment name and API version
/// straight into the request path and query string. A value containing `?`,
/// `#`, or `&` would rewrite the query; one containing `/` or `..` could
/// redirect the request to a different path entirely. These values normally
/// come from operator config rather than user input, so this is defense in
/// depth — but the project's zero-trust rule is to validate every parameter
/// regardless of source.
///
/// The allow-list is deliberately narrow: real Azure deployment names and API
/// versions are alphanumerics, hyphens, underscores, and dots.
///
/// # Errors
///
/// Returns [`Problem::Config`] when `value` is empty or contains a character
/// outside `[A-Za-z0-9._-]`.
pub(crate) fn validate_url_segment(field: &str, value: &str) -> Result<String> {
    let value = require_non_empty(field, value)?;
    if let Some(bad) = value
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '_' | '-'))
    {
        return Err(Problem::Config(format!(
            "{field} contains {bad:?}, which is not allowed in a URL segment \
(permitted: letters, digits, '.', '_', '-')"
        )));
    }
    // The character allow-list alone is NOT enough. `.` is permitted (real
    // deployment names contain it), so a bare `..` passes every per-character
    // check — and `/openai/deployments/../chat/completions` normalizes to
    // `/openai/chat/completions`, escaping the very path segment this guard
    // exists to pin. Reject any all-dots value, which covers `.`, `..`, and
    // longer runs while leaving `my.deployment-2` alone.
    if value.chars().all(|c| c == '.') {
        return Err(Problem::Config(format!(
            "{field} is {value:?}, a dot-segment that would alter the request path"
        )));
    }
    Ok(value)
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
    fn a_bare_dot_segment_is_rejected_even_though_dots_are_allowed() {
        // The character allow-list permits '.', so these pass every per-char
        // check; only the all-dots rule catches them.
        for hostile in [".", "..", "...", "...."] {
            assert!(
                validate_url_segment("deployment", hostile).is_err(),
                "{hostile:?} is a dot-segment and must be rejected"
            );
        }
    }

    #[test]
    fn dots_inside_a_real_name_are_still_allowed() {
        // The dot-segment rule must not reject legitimate names.
        for ok in ["my.deployment-2", "v1.0", "a.b.c"] {
            assert!(
                validate_url_segment("deployment", ok).is_ok(),
                "{ok:?} is well-formed and must be accepted"
            );
        }
    }

    #[test]
    fn credential_debug_never_reveals_the_secret_or_its_shape() {
        let secret = "sk-super-secret-value-12345";
        let rendered = format!("{:?}", Credential::new(secret));

        assert!(!rendered.contains(secret), "the value must not be printed");
        assert!(!rendered.contains("sk-"), "not even a prefix");
        assert!(
            !rendered.contains(&secret.len().to_string()),
            "not even the length, which narrows a brute force"
        );
        assert_eq!(rendered, "<redacted>");
    }

    #[test]
    fn credential_debug_is_identical_for_different_secrets() {
        // A rendering that varied with the value would leak through comparison.
        assert_eq!(
            format!("{:?}", Credential::new("short")),
            format!("{:?}", Credential::new("a-much-longer-secret-value"))
        );
    }

    #[test]
    fn credential_still_exposes_the_value_for_header_construction() {
        assert_eq!(Credential::new("sk-abc").expose(), "sk-abc");
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
