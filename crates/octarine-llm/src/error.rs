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
    let excerpt = excerpt(body);
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

/// Maximum characters of an upstream error body echoed into a [`Problem`].
const MAX_EXCERPT: usize = 200;

/// Truncates an error body to a bounded, char-safe excerpt.
///
/// Bounded because provider error bodies can be large, and a `Problem` message
/// may land in an audit record. Truncation is by `char` rather than by byte so a
/// multi-byte character is never split.
fn excerpt(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "<empty body>".to_string();
    }
    let mut out: String = trimmed.chars().take(MAX_EXCERPT).collect();
    if trimmed.chars().count() > MAX_EXCERPT {
        out.push('…');
    }
    out
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
    fn message_names_the_provider_and_status() {
        let problem = problem_for_status("anthropic", 401, "invalid x-api-key");
        let rendered = problem.to_string();
        assert!(rendered.contains("anthropic"), "must name the provider");
        assert!(rendered.contains("401"), "must carry the status");
        assert!(
            rendered.contains("invalid x-api-key"),
            "must echo the upstream body"
        );
    }

    #[test]
    fn long_bodies_are_truncated_with_an_ellipsis() {
        let long = "x".repeat(500);
        let rendered = problem_for_status("openai", 500, &long).to_string();
        assert!(rendered.contains('…'), "truncation must be marked");
        assert!(
            rendered.len() < 400,
            "a 500-char body must not land whole in the message, got {}",
            rendered.len()
        );
    }

    #[test]
    fn truncation_does_not_split_multibyte_characters() {
        // 300 multi-byte chars: a byte-based cut would panic or corrupt.
        let body = "é".repeat(300);
        let rendered = problem_for_status("openai", 500, &body).to_string();
        assert!(rendered.contains('é'));
        assert!(rendered.contains('…'));
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
