//! Metric names for LLM calls.
//!
//! Declared through octarine's [`define_metrics!`](octarine::define_metrics)
//! macro, which validates each name at construction and exposes them as
//! functions. The macro is `#[macro_export]`ed from `octarine-core`, so `$crate`
//! resolves correctly from this sibling crate.

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
