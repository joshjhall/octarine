//! Metric names for LLM calls.
//!
//! Declared through octarine's [`define_metrics!`](octarine::define_metrics)
//! macro, which validates each name at construction and exposes them as
//! functions. The macro is `#[macro_export]`ed from `octarine-core`, so `$crate`
//! resolves correctly from this sibling crate.
//!
//! # Dimensions are in the name, not in labels
//!
//! Issue #520 asks for `octarine_llm_calls_total{provider,model,outcome}`.
//! octarine's dimensional-metric type (`observe::metrics::LabeledMetric`) is
//! `pub(crate)` to `octarine-core`, so a sibling crate cannot reach it — and
//! widening that visibility purely to serve our own sibling is what rule R1 in
//! `docs/architecture/crate-layout.md` forbids.
//!
//! So the dimensions are encoded in the metric name instead:
//! `llm.recognizer.calls.openai.ok`. A Prometheus recording rule can split
//! those segments back into labels at scrape time, so the per-provider
//! breakdown the AC wants — "OpenAI's error rate vs Ollama's" — is still
//! answerable. The full free-text detail (latency, token counts, finish reason)
//! is on the per-call `observe` event, which is not visibility-constrained.
//!
//! Exposing `LabeledMetric` publicly and switching to real labels is the better
//! end state; it belongs to `octarine-core`, not here.

use octarine::observe::metrics::MetricName;

// The macro generates the `metric_names` module without a doc comment, which
// this crate's `missing_docs = "warn"` would flag. The module is an
// implementation detail of the macro, so the lint is silenced at the generation
// site rather than relaxed crate-wide.
#[allow(missing_docs)]
mod generated {
    octarine::define_metrics! {
        pub
        calls_total => "llm.recognizer.calls_total",
        call_duration_ms => "llm.recognizer.call_duration_ms",
        errors => "llm.recognizer.errors",
        prompt_tokens => "llm.recognizer.prompt_tokens",
        completion_tokens => "llm.recognizer.completion_tokens",
        cache_read_tokens => "llm.recognizer.cache_read_tokens",
        entities_detected => "llm.recognizer.entities_detected",
        parse_failures => "llm.recognizer.parse_failures",
        spans_unanchored => "llm.recognizer.spans_unanchored",
    }
}

pub use generated::metric_names;

/// How a call ended, forming the `outcome` dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Detection completed and results were returned.
    Ok,
    /// The provider call itself failed (transport, auth, rate limit).
    ProviderError,
    /// The provider answered but the response could not be parsed.
    ParseError,
}

impl Outcome {
    /// The name segment for this outcome.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ProviderError => "provider_error",
            Self::ParseError => "parse_error",
        }
    }
}

/// Builds a per-provider, per-outcome counter name.
///
/// Shape: `llm.recognizer.calls.<provider>.<outcome>` — for example
/// `llm.recognizer.calls.openai.ok`.
///
/// `provider` is sanitized to `[a-z0-9_]` so a hostile or merely unusual
/// provider name (these are caller-supplied for
/// [`OpenAiCompatibleProvider`](crate::OpenAiCompatibleProvider)) cannot inject
/// separators and forge a different metric.
///
/// Returns `None` if the assembled name is not a valid metric name, in which
/// case the caller should fall back to the undimensioned counter rather than
/// dropping the observation.
#[must_use]
pub fn calls_by_provider(provider: &str, outcome: Outcome) -> Option<MetricName> {
    let safe = sanitize_segment(provider);
    MetricName::new(format!("llm.recognizer.calls.{safe}.{}", outcome.as_str())).ok()
}

/// Builds a per-provider latency histogram name.
///
/// Shape: `llm.recognizer.duration_ms.<provider>`.
#[must_use]
pub fn duration_by_provider(provider: &str) -> Option<MetricName> {
    let safe = sanitize_segment(provider);
    MetricName::new(format!("llm.recognizer.duration_ms.{safe}")).ok()
}

/// Reduces a caller-supplied name to a safe metric-name segment.
///
/// Anything outside `[a-z0-9_]` becomes `_`, so a provider named
/// `"evil.name.ok"` cannot masquerade as another provider's outcome counter.
/// An empty result becomes `"unknown"` rather than producing a doubled
/// separator.
fn sanitize_segment(raw: &str) -> String {
    // Runs are collapsed and edges trimmed because `MetricName::new` rejects
    // consecutive separators and leading/trailing ones — a name like
    // "gpt..4o" would otherwise fail validation and silently drop the metric.
    let mut out = String::new();
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        return "unknown".to_string();
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn call_names_carry_provider_and_outcome() {
        let name = calls_by_provider("openai", Outcome::Ok).expect("valid");
        assert_eq!(name.as_str(), "llm.recognizer.calls.openai.ok");

        let err = calls_by_provider("ollama", Outcome::ProviderError).expect("valid");
        assert_eq!(err.as_str(), "llm.recognizer.calls.ollama.provider_error");
    }

    #[test]
    fn distinct_providers_produce_distinct_names() {
        // The whole point: OpenAI's error rate must be separable from Ollama's.
        let a = calls_by_provider("openai", Outcome::ProviderError).expect("valid");
        let b = calls_by_provider("ollama", Outcome::ProviderError).expect("valid");
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn distinct_outcomes_produce_distinct_names() {
        let ok = calls_by_provider("openai", Outcome::Ok).expect("valid");
        let parse = calls_by_provider("openai", Outcome::ParseError).expect("valid");
        let provider = calls_by_provider("openai", Outcome::ProviderError).expect("valid");

        assert_ne!(ok.as_str(), parse.as_str());
        assert_ne!(parse.as_str(), provider.as_str());
    }

    #[test]
    fn a_provider_name_cannot_forge_another_metric() {
        // Dots are the separator; a provider must not be able to inject them.
        let forged = calls_by_provider("openai.ok.evil", Outcome::ParseError).expect("valid");
        assert_eq!(
            forged.as_str(),
            "llm.recognizer.calls.openai_ok_evil.parse_error",
            "separators in a provider name must be neutralized"
        );
        assert!(!forged.as_str().contains("openai.ok"));
    }

    #[test]
    fn separator_runs_are_collapsed_so_the_name_stays_valid() {
        // MetricName::new rejects `__` and `..`; an uncollapsed run would make
        // this return None and silently drop the observation.
        let name = calls_by_provider("gpt...4o  turbo", Outcome::Ok)
            .expect("a messy provider name must still yield a valid metric");
        assert_eq!(name.as_str(), "llm.recognizer.calls.gpt_4o_turbo.ok");
    }

    #[test]
    fn edge_separators_are_trimmed() {
        let name = calls_by_provider(".openai.", Outcome::Ok).expect("valid");
        assert_eq!(name.as_str(), "llm.recognizer.calls.openai.ok");
    }

    #[test]
    fn provider_names_are_lowercased_so_case_does_not_split_a_series() {
        let upper = calls_by_provider("OpenAI", Outcome::Ok).expect("valid");
        let lower = calls_by_provider("openai", Outcome::Ok).expect("valid");
        assert_eq!(upper.as_str(), lower.as_str());
    }

    #[test]
    fn an_unusable_provider_name_becomes_unknown_not_a_doubled_separator() {
        let name = calls_by_provider("...", Outcome::Ok).expect("valid");
        assert_eq!(name.as_str(), "llm.recognizer.calls.unknown.ok");
    }

    #[test]
    fn duration_names_carry_the_provider() {
        let name = duration_by_provider("anthropic").expect("valid");
        assert_eq!(name.as_str(), "llm.recognizer.duration_ms.anthropic");
    }
}
