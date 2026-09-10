//! Mapping provider HTTP failures onto [`Problem`].
//!
//! Providers differ in wire format but not in failure taxonomy: a 401 is a
//! credential problem everywhere, a 429 is backpressure everywhere. Centralizing
//! the mapping keeps the five clients from each inventing their own.

use octarine_problem::Problem;
use std::time::Duration;

/// Converts an upstream HTTP status into a [`Problem`].
///
/// `provider` and `body` are woven into the message so a failure is traceable
/// to a specific backend without re-reading logs from the transport layer.
///
/// The mapping deliberately keeps `401`/`403` (credentials — never retryable)
/// distinct from `429` (backpressure — always retryable). Collapsing them into
/// a generic failure would let a retry layer hammer an endpoint that will keep
/// rejecting it.
#[must_use]
pub fn problem_for_status(provider: &str, status: u16, body: &str) -> Problem {
    let excerpt = classify(body);
    match status {
        401 | 403 => Problem::Auth(format!(
            "{provider} rejected the credentials (HTTP {status}): {excerpt}"
        )),
        404 => Problem::NotFound(format!(
            "{provider} endpoint or model (HTTP {status}): {excerpt}"
        )),
        // The Retry-After header is handled by the transport layer; the
        // duration here is a floor for callers inspecting the Problem itself.
        429 => Problem::RateLimited(Duration::from_secs(1)),
        408 | 504 => Problem::Timeout(format!("{provider} timed out (HTTP {status})")),
        400 | 422 => Problem::Validation(format!(
            "{provider} rejected the request (HTTP {status}): {excerpt}"
        )),
        500..=599 => Problem::Network(format!(
            "{provider} server error (HTTP {status}): {excerpt}"
        )),
        _ => Problem::OperationFailed(format!(
            "{provider} returned an unexpected HTTP {status}: {excerpt}"
        )),
    }
}

/// Maximum length of a provider error *code* echoed into a [`Problem`].
///
/// Codes are short identifiers (`invalid_api_key`, `rate_limit_exceeded`); a
/// longer value is not a code and is dropped.
const MAX_CODE_LEN: usize = 64;

/// Describes an error body without quoting its free text.
///
/// The body is **not** echoed. Providers routinely reflect part of the offending
/// request back in an error — a content-policy message quoting the flagged
/// passage, a "string too long" naming the payload — and this crate's requests
/// carry the text under analysis, so an excerpt would put the very PII being
/// detected into a `Problem` that `analyze` logs via `observe::warn`. That is
/// the leak already closed for parse errors; the same rule applies here.
///
/// What survives is a machine-readable classifier: the provider's own
/// `error.code` / `error.type` when the body is the usual JSON envelope, plus
/// the body length. Both are diagnostic and neither carries content.
fn classify(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "<empty body>".to_string();
    }

    match error_code(trimmed) {
        Some(code) => format!("code={code}, {} bytes", trimmed.len()),
        None => format!("{} bytes, no error code", trimmed.len()),
    }
}

/// Extracts `error.code` or `error.type` from a provider's JSON error envelope.
///
/// Returns `None` when the body is not JSON, has no such field, or the value is
/// implausibly long for a code — the latter guards against a provider stuffing
/// free text into the field and re-opening the leak.
fn error_code(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let error = value.get("error")?;
    let code = error
        .get("code")
        .or_else(|| error.get("type"))
        .and_then(serde_json::Value::as_str)?;

    if code.is_empty() || code.len() > MAX_CODE_LEN {
        return None;
    }
    // A code is an identifier; anything else is prose wearing a code's name.
    if !code
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return None;
    }
    Some(code.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn auth_failures_map_to_auth_not_a_generic_failure() {
        // Distinguishing these is the point: a retry layer must not re-send.
        assert!(matches!(
            problem_for_status("openai", 401, "bad key"),
            Problem::Auth(_)
        ));
        assert!(matches!(
            problem_for_status("openai", 403, "forbidden"),
            Problem::Auth(_)
        ));
    }

    #[test]
    fn rate_limit_maps_to_rate_limited_distinct_from_auth() {
        let problem = problem_for_status("anthropic", 429, "slow down");
        assert!(
            matches!(problem, Problem::RateLimited(_)),
            "429 must be retryable backpressure, not an auth failure"
        );
    }

    #[test]
    fn server_errors_map_to_network_across_the_whole_5xx_range() {
        for status in [500u16, 502, 503, 599] {
            assert!(
                matches!(
                    problem_for_status("ollama", status, "boom"),
                    Problem::Network(_)
                ),
                "HTTP {status} should be a Network problem"
            );
        }
    }

    #[test]
    fn gateway_timeout_is_a_timeout_not_a_generic_server_error() {
        // 504 sits inside 5xx but must bind to the earlier, more specific arm.
        assert!(matches!(
            problem_for_status("azure", 504, ""),
            Problem::Timeout(_)
        ));
    }

    #[test]
    fn client_validation_errors_map_to_validation() {
        assert!(matches!(
            problem_for_status("openai", 400, "bad request"),
            Problem::Validation(_)
        ));
        assert!(matches!(
            problem_for_status("openai", 422, "unprocessable"),
            Problem::Validation(_)
        ));
    }

    #[test]
    fn message_names_the_provider_and_status_without_echoing_the_body() {
        let problem = problem_for_status("anthropic", 401, "invalid x-api-key for user alice");
        let rendered = problem.to_string();

        assert!(rendered.contains("anthropic"), "must name the provider");
        assert!(rendered.contains("401"), "must carry the status");
        assert!(
            !rendered.contains("alice"),
            "the body must NOT be echoed, got: {rendered}"
        );
    }

    #[test]
    fn a_body_reflecting_the_analyzed_text_does_not_reach_the_message() {
        // The realistic leak: a content filter quoting the flagged passage,
        // which for this crate is the PII under analysis.
        let body = r#"{"error":{"code":"content_filter","message":"flagged: SSN 123-45-6789 for alice@example.com"}}"#;
        let rendered = problem_for_status("openai", 400, body).to_string();

        assert!(!rendered.contains("123-45-6789"), "got: {rendered}");
        assert!(!rendered.contains("alice@example.com"), "got: {rendered}");
        assert!(
            rendered.contains("content_filter"),
            "the machine-readable code IS kept, got: {rendered}"
        );
    }

    #[test]
    fn the_error_type_is_used_when_no_code_is_present() {
        let body = r#"{"error":{"type":"invalid_request_error","message":"secret prose"}}"#;
        let rendered = problem_for_status("openai", 400, body).to_string();

        assert!(rendered.contains("invalid_request_error"));
        assert!(!rendered.contains("secret prose"));
    }

    #[test]
    fn a_non_json_body_yields_only_its_length() {
        let rendered = problem_for_status("ollama", 500, "model llama3 not found").to_string();

        assert!(!rendered.contains("llama3"), "got: {rendered}");
        assert!(rendered.contains("bytes"), "the length survives");
    }

    #[test]
    fn prose_masquerading_as_a_code_is_rejected() {
        // A provider stuffing free text into `code` must not re-open the leak.
        let body = r#"{"error":{"code":"flagged text: alice@example.com was found"}}"#;
        let rendered = problem_for_status("openai", 400, body).to_string();

        assert!(!rendered.contains("alice@example.com"), "got: {rendered}");
        assert!(rendered.contains("no error code"));
    }

    #[test]
    fn an_overlong_code_is_rejected() {
        let long = "a".repeat(MAX_CODE_LEN + 1);
        let body = format!(r#"{{"error":{{"code":"{long}"}}}}"#);
        let rendered = problem_for_status("openai", 400, &body).to_string();

        assert!(!rendered.contains(&long));
        assert!(rendered.contains("no error code"));
    }

    #[test]
    fn empty_body_is_labelled_rather_than_blank() {
        let rendered = problem_for_status("ollama", 500, "   ").to_string();
        assert!(
            rendered.contains("<empty body>"),
            "an empty body should say so, not render as nothing"
        );
    }
}
