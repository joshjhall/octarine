//! The parallel batch anonymizer engine.
//!
//! [`BatchAnonymizerEngine`] anonymizes many texts at once on top of the
//! single-text [`AnonymizerEngine`](super::AnonymizerEngine). It is octarine's
//! day-one win over Presidio's `BatchAnonymizerEngine.anonymize_list`, which is
//! a sequential Python `for` loop: anonymizing one text is independent of every
//! other, so the batch loop is embarrassingly parallel and dispatched across
//! cores with `rayon`.
//!
//! Two entry points:
//!
//! - [`anonymize_list`](BatchAnonymizerEngine::anonymize_list) — a flat slice of
//!   texts with one detection list each, anonymized in parallel.
//! - [`anonymize_dict`](BatchAnonymizerEngine::anonymize_dict) — a nested
//!   [`serde_json::Value`], recursively anonymized with string-array values
//!   dispatched through `anonymize_list`.
//!
//! # Guarantees
//!
//! - **Order preserved.** `anonymize_list` returns results in input order
//!   regardless of the order worker threads finish (`rayon`'s indexed
//!   `collect`).
//! - **One failure fails the batch.** The first error in input order is
//!   returned and the rest of the batch is discarded. A per-item error policy
//!   may be added in a later issue if a user need arises.
//! - **Type passthrough.** In `anonymize_dict`, non-string JSON values
//!   (numbers, booleans, null) pass through unchanged — documented behavior, not
//!   best-effort silence.

use std::collections::HashMap;

use octarine_problem::{Problem, Result};
use rayon::prelude::*;
use serde_json::{Map, Value};

use super::AnonymizerEngine;
use crate::anonymize::{EngineResult, OperatorConfig, RecognizerResult};
use crate::observe;
use crate::observe::metrics::{increment, increment_by, record};

crate::define_metrics! {
    batch_anonymize_total       => "anonymize.batch.anonymize_total",
    batch_anonymize_duration_ms => "anonymize.batch.duration_ms",
    batch_anonymize_items_total => "anonymize.batch.items_total",
}

/// Anonymizes lists and nested-dict inputs in parallel via `rayon`.
///
/// Wraps an [`AnonymizerEngine`] and fans each text out across the `rayon`
/// thread pool. Construct with [`new`](BatchAnonymizerEngine::new) for the
/// built-in operator set, or [`with_engine`](BatchAnonymizerEngine::with_engine)
/// to supply a pre-configured engine (custom operators, conflict strategy).
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use octarine::anonymize::{BatchAnonymizerEngine, OperatorConfig, RecognizerResult};
///
/// let batch = BatchAnonymizerEngine::new();
/// let texts = ["SSN 123-45-6789.", "no pii here"];
/// let results = vec![
///     vec![RecognizerResult::new("US_SSN", 4, 15, 0.95)?],
///     vec![],
/// ];
/// let ops = HashMap::new(); // default `replace`
/// let out = batch.anonymize_list(&texts, &results, &ops)?;
/// assert_eq!(out.len(), 2);
/// assert_eq!(out.first().and_then(|r| r.text.as_deref()), Some("SSN <US_SSN>."));
/// assert_eq!(out.get(1).and_then(|r| r.text.as_deref()), Some("no pii here"));
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
pub struct BatchAnonymizerEngine {
    /// The inner single-text engine. Held `.silent()` so a large batch does not
    /// flood the metrics pipeline with one event per item — the batch engine
    /// emits aggregate metrics once per call instead.
    engine: AnonymizerEngine,
    emit_events: bool,
}

impl std::fmt::Debug for BatchAnonymizerEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchAnonymizerEngine")
            .field("engine", &self.engine)
            .field("emit_events", &self.emit_events)
            .finish()
    }
}

impl Default for BatchAnonymizerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchAnonymizerEngine {
    /// Creates a batch engine over a default [`AnonymizerEngine`] (the built-in
    /// `replace`, `redact`, `mask`, `hash`, `encrypt`, `decrypt` operators).
    ///
    /// The inner engine is run in silent mode; the batch engine emits aggregate
    /// metrics instead of per-item ones.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: AnonymizerEngine::new().silent(),
            emit_events: true,
        }
    }

    /// Creates a batch engine over a caller-supplied [`AnonymizerEngine`].
    ///
    /// Use this to batch with custom operators or a non-default conflict
    /// strategy. The provided engine is used as-is; call
    /// [`AnonymizerEngine::silent`] on it first if you want to suppress its
    /// per-item instrumentation under a large batch (recommended).
    #[must_use]
    pub fn with_engine(engine: AnonymizerEngine) -> Self {
        Self {
            engine,
            emit_events: true,
        }
    }

    /// Disables the batch engine's aggregate metric/event emission, returning
    /// `self` for chaining.
    #[must_use]
    pub fn silent(mut self) -> Self {
        self.emit_events = false;
        self
    }

    /// Anonymizes a slice of `texts` in parallel, applying `operators` per entity
    /// type, with one detection list per text.
    ///
    /// `texts[i]` is anonymized using `results[i]`, so the two slices must be the
    /// same length. Work is dispatched across the `rayon` thread pool; the
    /// returned vector is in input order regardless of completion order.
    ///
    /// This is the parallel replacement for Presidio's sequential
    /// `anonymize_list` loop.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if `texts.len() != results.len()`.
    /// Otherwise returns the **first** error in input order from any item's
    /// [`AnonymizerEngine::anonymize`] (an unknown operator, an invalid config,
    /// or an out-of-bounds/non-char-boundary span), discarding the rest of the
    /// batch.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use octarine::anonymize::{BatchAnonymizerEngine, OperatorConfig, RecognizerResult};
    ///
    /// let batch = BatchAnonymizerEngine::new();
    /// let texts = ["email a@b.co", "email c@d.co"];
    /// let results = vec![
    ///     vec![RecognizerResult::new("EMAIL_ADDRESS", 6, 12, 0.95)?],
    ///     vec![RecognizerResult::new("EMAIL_ADDRESS", 6, 12, 0.95)?],
    /// ];
    /// let mut ops = HashMap::new();
    /// ops.insert("EMAIL_ADDRESS".to_string(), OperatorConfig::new("redact")?);
    /// let out = batch.anonymize_list(&texts, &results, &ops)?;
    /// assert_eq!(out.first().and_then(|r| r.text.as_deref()), Some("email "));
    /// assert_eq!(out.get(1).and_then(|r| r.text.as_deref()), Some("email "));
    /// # Ok::<(), octarine_problem::Problem>(())
    /// ```
    pub fn anonymize_list(
        &self,
        texts: &[&str],
        results: &[Vec<RecognizerResult>],
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<Vec<EngineResult>> {
        let start = std::time::Instant::now();
        let outcome = self.anonymize_list_inner(texts, results, operators);

        if self.emit_events {
            record(
                metric_names::batch_anonymize_duration_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            increment(metric_names::batch_anonymize_total());
            match &outcome {
                Ok(out) => {
                    // Count items only on success — a failed batch anonymized
                    // zero items, so incrementing by `texts.len()` on the error
                    // path would inflate the "items processed" counter.
                    increment_by(
                        metric_names::batch_anonymize_items_total(),
                        out.len() as u64,
                    );
                    observe::debug(
                        "batch_anonymize",
                        format!("anonymized {} text(s) in parallel", out.len()),
                    );
                }
                Err(_) => observe::warn("batch_anonymize", "batch anonymize failed"),
            }
        }

        outcome
    }

    /// The un-instrumented parallel core of
    /// [`anonymize_list`](Self::anonymize_list).
    ///
    /// Validates the length invariant and fans the items across the `rayon`
    /// thread pool, emitting no metrics or events. Used directly by the
    /// recursive [`anonymize_dict`](Self::anonymize_dict) traversal so that a
    /// dict call emits one aggregate metric rather than one per nested array.
    ///
    /// `par_iter().zip(...).collect::<Result<Vec<_>>>()` over an indexed
    /// iterator preserves input order and short-circuits to the first error in
    /// index order — satisfying both the order-preservation and the
    /// one-failure-fails-batch contracts. `anonymize` takes the detection vector
    /// by value, so each item's results are cloned for the call.
    fn anonymize_list_inner(
        &self,
        texts: &[&str],
        results: &[Vec<RecognizerResult>],
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<Vec<EngineResult>> {
        if texts.len() != results.len() {
            return Err(Problem::Validation(format!(
                "batch anonymize_list length mismatch: {} texts but {} result lists",
                texts.len(),
                results.len()
            )));
        }

        texts
            .par_iter()
            .zip(results.par_iter())
            .map(|(text, item_results)| {
                self.engine.anonymize(text, item_results.clone(), operators)
            })
            .collect()
    }

    /// Anonymizes a nested [`serde_json::Value`], recursing into objects and
    /// arrays and dispatching string-array values to
    /// [`anonymize_list`](Self::anonymize_list).
    ///
    /// `results_by_path` maps a JSON **path** to the detections for the string
    /// at that path. Paths are dot-separated: object keys join with `.` and
    /// array elements use their numeric index, so the email in
    /// `{"users":[{"email":"a@b.co"}]}` is at path `users.0.email`. The root
    /// value's own path is the empty string `""`.
    ///
    /// Strings with no entry in `results_by_path` are returned unchanged.
    /// Non-string scalars (numbers, booleans, null) always pass through
    /// unchanged. Object key sets and array lengths are preserved.
    ///
    /// # Path ambiguity (caller contract)
    ///
    /// The `.` separator is **not escaped**, so the dotted path is ambiguous
    /// when an object key itself contains `.` or is an all-digits string. For
    /// example a top-level key `"user.email"` and the nested field in
    /// `{"user": {"email": …}}` both render as the path `user.email`, and a
    /// top-level key `"0"` collides with the first element of a sibling array.
    /// Such a collision routes a detection to the wrong field (or skips one),
    /// which in a PII context risks leaving a value un-anonymized. Callers whose
    /// keys may contain `.` or be numeric must disambiguate upstream (rename or
    /// pre-escape the keys) before building `results_by_path`. A future revision
    /// may switch to an escaped encoding (e.g. JSON Pointer, RFC 6901); the
    /// dot-path form is the documented contract until then.
    ///
    /// # Errors
    ///
    /// Returns the first [`Problem`] encountered while anonymizing any string in
    /// the structure (see [`anonymize_list`](Self::anonymize_list)).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use serde_json::json;
    /// use octarine::anonymize::{BatchAnonymizerEngine, OperatorConfig, RecognizerResult};
    ///
    /// let batch = BatchAnonymizerEngine::new();
    /// let input = json!({ "user": { "email": "a@b.co" }, "age": 42 });
    /// let mut by_path = HashMap::new();
    /// by_path.insert(
    ///     "user.email".to_string(),
    ///     vec![RecognizerResult::new("EMAIL_ADDRESS", 0, 6, 0.95)?],
    /// );
    /// let mut ops = HashMap::new();
    /// ops.insert("EMAIL_ADDRESS".to_string(), OperatorConfig::new("redact")?);
    /// let out = batch.anonymize_dict(&input, &by_path, &ops)?;
    /// assert_eq!(out, json!({ "user": { "email": "" }, "age": 42 }));
    /// # Ok::<(), octarine_problem::Problem>(())
    /// ```
    pub fn anonymize_dict(
        &self,
        value: &Value,
        results_by_path: &HashMap<String, Vec<RecognizerResult>>,
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<Value> {
        let start = std::time::Instant::now();
        let outcome = self.anonymize_value(value, "", results_by_path, operators);

        if self.emit_events {
            record(
                metric_names::batch_anonymize_duration_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            increment(metric_names::batch_anonymize_total());
            match &outcome {
                Ok(_) => observe::debug("batch_anonymize", "anonymized nested dict"),
                Err(_) => observe::warn("batch_anonymize", "batch anonymize_dict failed"),
            }
        }

        outcome
    }

    /// Recursively anonymizes one JSON `value` at `path`.
    ///
    /// Objects and non-string arrays recurse element-wise; an all-string array
    /// is dispatched to the un-instrumented `anonymize_list_inner` so its
    /// elements anonymize in parallel without double-emitting metrics; a string
    /// is anonymized when `results_by_path` has an entry for `path`; every other
    /// scalar passes through unchanged.
    fn anonymize_value(
        &self,
        value: &Value,
        path: &str,
        results_by_path: &HashMap<String, Vec<RecognizerResult>>,
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<Value> {
        match value {
            Value::Object(map) => {
                let mut out = Map::with_capacity(map.len());
                for (key, child) in map {
                    let child_path = join_path(path, key);
                    out.insert(
                        key.clone(),
                        self.anonymize_value(child, &child_path, results_by_path, operators)?,
                    );
                }
                Ok(Value::Object(out))
            }
            Value::Array(items) => {
                // Fast path: an array of all strings is a batch — anonymize its
                // elements in parallel through `anonymize_list`.
                if !items.is_empty() && items.iter().all(Value::is_string) {
                    let texts: Vec<&str> = items
                        .iter()
                        .map(|v| v.as_str().unwrap_or_default())
                        .collect();
                    let per_item: Vec<Vec<RecognizerResult>> = (0..items.len())
                        .map(|i| {
                            let elem_path = join_index(path, i);
                            results_by_path.get(&elem_path).cloned().unwrap_or_default()
                        })
                        .collect();
                    // Call the un-instrumented core: `anonymize_dict` emits one
                    // aggregate metric for the whole traversal, so nested array
                    // batches must not each emit their own.
                    let anonymized = self.anonymize_list_inner(&texts, &per_item, operators)?;
                    let out: Vec<Value> = anonymized
                        .into_iter()
                        .map(|r| Value::String(r.text.unwrap_or_default()))
                        .collect();
                    return Ok(Value::Array(out));
                }
                // Mixed/non-string array: recurse element-wise by index.
                let mut out = Vec::with_capacity(items.len());
                for (i, child) in items.iter().enumerate() {
                    let child_path = join_index(path, i);
                    out.push(self.anonymize_value(
                        child,
                        &child_path,
                        results_by_path,
                        operators,
                    )?);
                }
                Ok(Value::Array(out))
            }
            Value::String(s) => match results_by_path.get(path) {
                Some(item_results) => {
                    let result = self.engine.anonymize(s, item_results.clone(), operators)?;
                    Ok(Value::String(result.text.unwrap_or_default()))
                }
                // No detections for this path: pass the string through unchanged.
                None => Ok(value.clone()),
            },
            // Type passthrough: numbers, booleans, and null are never strings, so
            // they carry no PII and are returned verbatim.
            Value::Number(_) | Value::Bool(_) | Value::Null => Ok(value.clone()),
        }
    }
}

/// Joins a parent `path` with an object `key`, using `.` as the separator.
/// At the root (`path` empty) the key stands alone.
fn join_path(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

/// Joins a parent `path` with an array `index`, using `.` as the separator.
/// At the root (`path` empty) the index stands alone.
fn join_index(path: &str, index: usize) -> String {
    if path.is_empty() {
        index.to_string()
    } else {
        format!("{path}.{index}")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn rr(entity: &str, start: usize, end: usize) -> RecognizerResult {
        RecognizerResult::new(entity, start, end, 0.95).expect("valid result")
    }

    fn redact_ops() -> HashMap<String, OperatorConfig> {
        let mut ops = HashMap::new();
        ops.insert(
            "DEFAULT".to_string(),
            OperatorConfig::new("redact").expect("cfg"),
        );
        ops
    }

    #[test]
    fn empty_list_returns_empty() {
        let batch = BatchAnonymizerEngine::new();
        let out = batch
            .anonymize_list(&[], &[], &HashMap::new())
            .expect("anonymize_list");
        assert!(out.is_empty());
    }

    #[test]
    fn length_mismatch_errors() {
        let batch = BatchAnonymizerEngine::new();
        let texts = ["a", "b"];
        let results = vec![vec![]]; // only one list for two texts
        let err = batch.anonymize_list(&texts, &results, &HashMap::new());
        assert!(err.is_err());
    }

    #[test]
    fn list_default_replace_per_item() {
        let batch = BatchAnonymizerEngine::new();
        let texts = ["SSN 123-45-6789.", "no pii"];
        let results = vec![vec![rr("US_SSN", 4, 15)], vec![]];
        let out = batch
            .anonymize_list(&texts, &results, &HashMap::new())
            .expect("anonymize_list");
        assert_eq!(out.len(), 2);
        assert_eq!(
            out.first().expect("item 0").text.as_deref(),
            Some("SSN <US_SSN>.")
        );
        assert_eq!(out.get(1).expect("item 1").text.as_deref(), Some("no pii"));
    }

    #[test]
    fn list_1000_items_preserves_order() {
        let batch = BatchAnonymizerEngine::new();
        // Each text is uniquely tagged with its index so we can assert that
        // output[i] corresponds to input[i] after the parallel run.
        let texts: Vec<String> = (0..1000)
            .map(|i| format!("user{i} ssn 123-45-6789"))
            .collect();
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        // "123-45-6789" sits at the tail of each string; compute its span once
        // per item (prefix length varies with the index width).
        let results: Vec<Vec<RecognizerResult>> = texts
            .iter()
            .map(|t| {
                let start = t.find("123-45-6789").expect("ssn present");
                vec![rr("US_SSN", start, start + "123-45-6789".len())]
            })
            .collect();

        let out = batch
            .anonymize_list(&refs, &results, &HashMap::new())
            .expect("anonymize_list");

        assert_eq!(out.len(), 1000);
        for (i, result) in out.iter().enumerate() {
            let text = result.text.as_deref().expect("text");
            // Output i must still carry the index-i tag (stable ordering) and
            // have had its SSN replaced.
            assert_eq!(text, format!("user{i} ssn <US_SSN>"));
        }
    }

    #[test]
    fn one_item_failure_fails_whole_batch() {
        let batch = BatchAnonymizerEngine::new();
        let texts = ["ok text", "short"];
        // Second item has an out-of-bounds span → whole batch errors.
        let results = vec![vec![], vec![rr("X", 2, 99)]];
        let err = batch.anonymize_list(&texts, &results, &HashMap::new());
        assert!(err.is_err());
    }

    #[test]
    fn dict_nested_users_anonymizes_and_preserves_structure() {
        let batch = BatchAnonymizerEngine::new();
        let input = json!({
            "users": [
                { "email": "a@b.co" },
                { "email": "c@d.co" },
            ]
        });
        let mut by_path = HashMap::new();
        // Whole-string email spans (0..len of each address).
        by_path.insert("users.0.email".to_string(), vec![rr("EMAIL_ADDRESS", 0, 6)]);
        by_path.insert("users.1.email".to_string(), vec![rr("EMAIL_ADDRESS", 0, 6)]);

        let out = batch
            .anonymize_dict(&input, &by_path, &redact_ops())
            .expect("anonymize_dict");

        assert_eq!(
            out,
            json!({
                "users": [
                    { "email": "" },
                    { "email": "" },
                ]
            })
        );
    }

    #[test]
    fn dict_type_passthrough_for_non_strings() {
        let batch = BatchAnonymizerEngine::new();
        let input = json!({
            "name": "Bob",
            "age": 42,
            "active": true,
            "nickname": null,
            "score": 3.5,
        });
        let mut by_path = HashMap::new();
        by_path.insert("name".to_string(), vec![rr("PERSON", 0, 3)]);

        let out = batch
            .anonymize_dict(&input, &by_path, &HashMap::new())
            .expect("anonymize_dict");

        // String anonymized; number, bool, null, float untouched.
        assert_eq!(out.get("name").and_then(Value::as_str), Some("<PERSON>"));
        assert_eq!(out.get("age"), Some(&json!(42)));
        assert_eq!(out.get("active"), Some(&json!(true)));
        assert_eq!(out.get("nickname"), Some(&Value::Null));
        assert_eq!(out.get("score"), Some(&json!(3.5)));
    }

    #[test]
    fn dict_string_array_fast_path() {
        let batch = BatchAnonymizerEngine::new();
        let input = json!({ "tags": ["a@b.co", "c@d.co"] });
        let mut by_path = HashMap::new();
        by_path.insert("tags.0".to_string(), vec![rr("EMAIL_ADDRESS", 0, 6)]);
        by_path.insert("tags.1".to_string(), vec![rr("EMAIL_ADDRESS", 0, 6)]);

        let out = batch
            .anonymize_dict(&input, &by_path, &redact_ops())
            .expect("anonymize_dict");

        assert_eq!(out, json!({ "tags": ["", ""] }));
    }

    #[test]
    fn dict_string_without_path_is_unchanged() {
        let batch = BatchAnonymizerEngine::new();
        let input = json!({ "note": "leave me alone" });
        let out = batch
            .anonymize_dict(&input, &HashMap::new(), &HashMap::new())
            .expect("anonymize_dict");
        assert_eq!(out, input);
    }

    #[test]
    fn dict_error_path_propagates() {
        // A string value paired with an out-of-bounds span makes the inner
        // anonymize fail; the dict call must surface that error, not swallow it.
        let batch = BatchAnonymizerEngine::new();
        let input = json!({ "note": "hi" });
        let mut by_path = HashMap::new();
        by_path.insert("note".to_string(), vec![rr("X", 2, 99)]);
        let err = batch.anonymize_dict(&input, &by_path, &HashMap::new());
        assert!(err.is_err());
    }

    #[test]
    fn dict_empty_array_unchanged() {
        // An empty array skips the all-string fast path (the `!is_empty` guard)
        // and falls through the element-wise loop to an empty array output.
        let batch = BatchAnonymizerEngine::new();
        let input = json!({ "tags": [] });
        let out = batch
            .anonymize_dict(&input, &HashMap::new(), &HashMap::new())
            .expect("anonymize_dict");
        assert_eq!(out, json!({ "tags": [] }));
    }

    #[test]
    fn dict_silent_still_transforms() {
        // Covers the anonymize_dict branch under emit_events = false.
        let batch = BatchAnonymizerEngine::new().silent();
        let input = json!({ "name": "Bob" });
        let mut by_path = HashMap::new();
        by_path.insert("name".to_string(), vec![rr("PERSON", 0, 3)]);
        let out = batch
            .anonymize_dict(&input, &by_path, &HashMap::new())
            .expect("anonymize_dict");
        assert_eq!(out, json!({ "name": "<PERSON>" }));
    }

    #[test]
    fn default_and_debug_impls() {
        // Exercise the hand-written Default and Debug impls.
        let batch = BatchAnonymizerEngine::default();
        let rendered = format!("{batch:?}");
        assert!(rendered.contains("BatchAnonymizerEngine"));
    }

    #[test]
    fn dict_mixed_array_recurses_by_index() {
        let batch = BatchAnonymizerEngine::new();
        // Mixed array (string + number) takes the element-wise recursion path,
        // not the all-string fast path.
        let input = json!({ "vals": ["Bob", 7] });
        let mut by_path = HashMap::new();
        by_path.insert("vals.0".to_string(), vec![rr("PERSON", 0, 3)]);

        let out = batch
            .anonymize_dict(&input, &by_path, &HashMap::new())
            .expect("anonymize_dict");

        assert_eq!(out, json!({ "vals": ["<PERSON>", 7] }));
    }

    #[test]
    fn silent_batch_still_transforms() {
        let batch = BatchAnonymizerEngine::new().silent();
        let texts = ["Bob"];
        let results = vec![vec![rr("PERSON", 0, 3)]];
        let out = batch
            .anonymize_list(&texts, &results, &HashMap::new())
            .expect("anonymize_list");
        assert_eq!(out.first().expect("item").text.as_deref(), Some("<PERSON>"));
    }

    #[test]
    fn with_engine_uses_custom_engine() {
        use crate::anonymize::{AnonymizerEngine, ConflictResolutionStrategy};
        let engine = AnonymizerEngine::new()
            .with_conflict_strategy(ConflictResolutionStrategy::None)
            .silent();
        let batch = BatchAnonymizerEngine::with_engine(engine);
        let texts = ["Bob"];
        let results = vec![vec![rr("PERSON", 0, 3)]];
        let out = batch
            .anonymize_list(&texts, &results, &HashMap::new())
            .expect("anonymize_list");
        assert_eq!(out.first().expect("item").text.as_deref(), Some("<PERSON>"));
    }

    // --- Performance (ignored by default; run via `just test-perf`) ----------

    #[test]
    #[ignore = "perf: run via `just test-perf`"]
    fn test_perf_batch_parallel_speedup() {
        // Compares parallel `anonymize_list` wall-time against a sequential
        // baseline over the same engine. The issue targets >=4x on an 8-core
        // CI runner; we assert a conservative >1.5x to stay non-flaky on
        // contended/low-core machines while still proving parallelism helps.
        let n = 50_000;
        let texts: Vec<String> = (0..n).map(|i| format!("user{i} ssn 123-45-6789")).collect();
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let results: Vec<Vec<RecognizerResult>> = texts
            .iter()
            .map(|t| {
                let start = t.find("123-45-6789").expect("ssn present");
                vec![rr("US_SSN", start, start + "123-45-6789".len())]
            })
            .collect();
        let ops = HashMap::new();

        let batch = BatchAnonymizerEngine::new().silent();
        let seq_engine = AnonymizerEngine::new().silent();

        // Sequential baseline.
        let seq_start = std::time::Instant::now();
        let seq: Vec<EngineResult> = refs
            .iter()
            .zip(results.iter())
            .map(|(t, r)| seq_engine.anonymize(t, r.clone(), &ops).expect("seq"))
            .collect();
        let seq_elapsed = seq_start.elapsed();

        // Parallel.
        let par_start = std::time::Instant::now();
        let par = batch
            .anonymize_list(&refs, &results, &ops)
            .expect("anonymize_list");
        let par_elapsed = par_start.elapsed();

        assert_eq!(seq.len(), par.len());
        let speedup = seq_elapsed.as_secs_f64() / par_elapsed.as_secs_f64();
        assert!(
            speedup > 1.5,
            "expected parallel speedup > 1.5x, got {speedup:.2}x \
             (seq {seq_elapsed:?}, par {par_elapsed:?})"
        );
    }
}
