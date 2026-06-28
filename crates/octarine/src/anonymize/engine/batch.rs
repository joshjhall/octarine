//! The parallel batch anonymizer and deanonymizer engines.
// arch-check: allow file-length -- two symmetric sibling engines (anonymize +
// deanonymize) the issue (#513) mandates share this file with #ENG-BATCH-ANON;
// they share the module doc, the `define_metrics!` block, and the path helpers,
// and the bulk is doc comments + doctests, not branching logic.
//!
//! [`BatchAnonymizerEngine`] anonymizes many texts at once on top of the
//! single-text [`AnonymizerEngine`](super::AnonymizerEngine). It is octarine's
//! day-one win over Presidio's `BatchAnonymizerEngine.anonymize_list`, which is
//! a sequential Python `for` loop: anonymizing one text is independent of every
//! other, so the batch loop is embarrassingly parallel and dispatched across
//! cores with `rayon`.
//!
//! [`BatchDeanonymizeEngine`] is the symmetric reverse surface. Presidio's
//! `DeanonymizeEngine` is single-text only — there is no batch deanonymizer at
//! all — so the parallel `deanonymize_list` / `deanonymize_dict` pair is a pure
//! octarine extension. It reverses through the same sync engine path that the
//! sync `Custom` / [`Decrypt`](crate::anonymize::Decrypt) reverse operators use:
//! the direction is decided by which operators the caller configures, not by a
//! separate engine type.
//!
//! Four entry points:
//!
//! - [`anonymize_list`](BatchAnonymizerEngine::anonymize_list) — a flat slice of
//!   texts with one detection list each, anonymized in parallel.
//! - [`anonymize_dict`](BatchAnonymizerEngine::anonymize_dict) — a nested
//!   [`serde_json::Value`], recursively anonymized with string-array values
//!   dispatched through `anonymize_list`.
//! - [`deanonymize_list`](BatchDeanonymizeEngine::deanonymize_list) — a flat
//!   slice of anonymized texts with one [`OperatorResult`] list each (the
//!   `EngineResult.items` of a prior anonymize pass), reversed in parallel.
//! - [`deanonymize_dict`](BatchDeanonymizeEngine::deanonymize_dict) — the
//!   nested-dict counterpart, mirroring `anonymize_dict` recursion.
//!
//! # Guarantees
//!
//! - **Order preserved.** Every list entry point returns results in input order
//!   regardless of the order worker threads finish (`rayon`'s indexed
//!   `collect`).
//! - **Anonymize: one failure fails the batch.** The first error in input order
//!   is returned and the rest of the batch is discarded.
//! - **Deanonymize: symmetric error semantics.** By default one item's failure
//!   does **not** fail the whole batch — the failed slot is returned as a
//!   passthrough [`EngineResult`] (the input text, still anonymized, left
//!   intact) carrying a single `DEANONYMIZE_ERROR` [`OperatorResult`] so the
//!   per-item error is collected in `EngineResult.items` rather than silently
//!   dropped. [`strict`](BatchDeanonymizeEngine::strict) opts back in to
//!   fail-fast (first error in input order fails the batch).
//! - **Type passthrough.** In both dict traversals, non-string JSON values
//!   (numbers, booleans, null) pass through unchanged — documented behavior, not
//!   best-effort silence.

use std::collections::HashMap;

use octarine_problem::{Problem, Result};
use rayon::prelude::*;
use serde_json::{Map, Value};

use super::AnonymizerEngine;
use crate::anonymize::{EngineResult, OperatorConfig, OperatorResult, RecognizerResult};
use crate::observe;
use crate::observe::metrics::{increment, increment_by, record};

crate::define_metrics! {
    batch_anonymize_total         => "anonymize.batch.anonymize_total",
    batch_anonymize_duration_ms   => "anonymize.batch.duration_ms",
    batch_anonymize_items_total   => "anonymize.batch.items_total",
    batch_deanonymize_total       => "anonymize.batch.deanonymize_total",
    batch_deanonymize_duration_ms => "anonymize.batch.deanonymize_duration_ms",
    batch_deanonymize_items_total => "anonymize.batch.deanonymize_items_total",
}

/// Entity-type label used on the synthetic [`OperatorResult`] that records a
/// per-item deanonymize failure in non-strict mode.
const DEANONYMIZE_ERROR_ENTITY: &str = "DEANONYMIZE_ERROR";

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

/// Reverses anonymized lists and nested-dict inputs in parallel via `rayon`.
///
/// The symmetric counterpart to [`BatchAnonymizerEngine`], and a pure octarine
/// extension: Presidio's `DeanonymizeEngine` is single-text only, so there is no
/// batch deanonymizer to match. Reversing runs through the **sync** engine path
/// (the same one the sync [`Custom`](crate::anonymize::Custom) reverse closure
/// and [`Decrypt`](crate::anonymize::Decrypt) use); the async, vault-backed
/// deanonymize path is single-text only by invariant and is not batched here.
///
/// Construct with [`new`](BatchDeanonymizeEngine::new) for the built-in operator
/// set (which includes `decrypt`), or [`with_engine`](BatchDeanonymizeEngine::with_engine)
/// to supply an engine carrying custom reverse operators.
///
/// # Error semantics
///
/// Unlike the anonymize batch — where one failure fails the whole batch — the
/// deanonymize batch is **lenient by default**: a single item that fails to
/// reverse (a tampered ciphertext, a wrong key, a bad span) does not discard the
/// rest. Its slot is returned as a passthrough [`EngineResult`] whose `text` is
/// the still-anonymized input and whose single `items` entry is a
/// `DEANONYMIZE_ERROR` [`OperatorResult`] carrying the error message — the error
/// is collected, never silently swallowed, and the safe (anonymized) value is
/// preserved. Call [`strict`](BatchDeanonymizeEngine::strict) to fail the batch
/// on the first error in input order instead.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use serde_json::json;
/// use octarine::anonymize::{
///     BatchAnonymizerEngine, BatchDeanonymizeEngine, OperatorConfig, RecognizerResult,
/// };
///
/// // Round-trip: encrypt a batch, then decrypt it back.
/// let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// let mut enc = HashMap::new();
/// enc.insert("US_SSN".to_string(), OperatorConfig::with_params("encrypt", {
///     let mut p = HashMap::new();
///     p.insert("key".to_string(), json!(key));
///     p
/// })?);
/// let mut dec = HashMap::new();
/// dec.insert("US_SSN".to_string(), OperatorConfig::with_params("decrypt", {
///     let mut p = HashMap::new();
///     p.insert("key".to_string(), json!(key));
///     p
/// })?);
///
/// let texts = ["SSN 123-45-6789."];
/// let results = vec![vec![RecognizerResult::new("US_SSN", 4, 15, 0.95)?]];
/// let anon = BatchAnonymizerEngine::new().anonymize_list(&texts, &results, &enc)?;
///
/// // Feed the anonymized text + its operator items straight back to deanonymize.
/// let anon_texts: Vec<&str> = anon.iter().map(|r| r.text.as_deref().unwrap_or_default()).collect();
/// let items: Vec<Vec<_>> = anon.iter().map(|r| r.items.clone()).collect();
/// let restored = BatchDeanonymizeEngine::new().deanonymize_list(&anon_texts, &items, &dec)?;
/// assert_eq!(restored.first().and_then(|r| r.text.as_deref()), Some("SSN 123-45-6789."));
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
pub struct BatchDeanonymizeEngine {
    /// The inner single-text engine, held `.silent()` so a large batch does not
    /// flood the metrics pipeline with one event per item.
    engine: AnonymizerEngine,
    emit_events: bool,
    /// When `true`, the first item failure in input order fails the whole batch;
    /// when `false` (default) failures are collected per item (see the
    /// type-level error-semantics note).
    strict: bool,
}

impl std::fmt::Debug for BatchDeanonymizeEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchDeanonymizeEngine")
            .field("engine", &self.engine)
            .field("emit_events", &self.emit_events)
            .field("strict", &self.strict)
            .finish()
    }
}

impl Default for BatchDeanonymizeEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchDeanonymizeEngine {
    /// Creates a batch deanonymize engine over a default [`AnonymizerEngine`].
    ///
    /// The default engine registers the built-in operators, including the
    /// reversing `decrypt`. The inner engine runs in silent mode; the batch
    /// engine emits aggregate metrics instead of per-item ones. Lenient (non-
    /// strict) error semantics are the default.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: AnonymizerEngine::new().silent(),
            emit_events: true,
            strict: false,
        }
    }

    /// Creates a batch deanonymize engine over a caller-supplied
    /// [`AnonymizerEngine`].
    ///
    /// Use this to reverse with custom operators (e.g. a sync
    /// [`Custom::deanonymizer`](crate::anonymize::Custom::deanonymizer) closure)
    /// or a non-default conflict strategy. Call [`AnonymizerEngine::silent`] on
    /// the engine first to suppress its per-item instrumentation under a large
    /// batch (recommended).
    #[must_use]
    pub fn with_engine(engine: AnonymizerEngine) -> Self {
        Self {
            engine,
            emit_events: true,
            strict: false,
        }
    }

    /// Disables the batch engine's aggregate metric/event emission, returning
    /// `self` for chaining.
    #[must_use]
    pub fn silent(mut self) -> Self {
        self.emit_events = false;
        self
    }

    /// Switches to fail-fast error semantics, returning `self` for chaining.
    ///
    /// In strict mode the first item that fails to reverse (in input order)
    /// fails the whole batch, matching [`BatchAnonymizerEngine`]'s
    /// one-failure-fails-the-batch contract. The default is lenient: failures
    /// are collected per item and the rest of the batch still reverses.
    #[must_use]
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Deanonymizes a slice of `texts` in parallel, reversing each through the
    /// configured `operators`, with one [`OperatorResult`] list per text.
    ///
    /// `texts[i]` is reversed using `operator_results[i]` — typically the
    /// `EngineResult.items` produced when `texts[i]` was anonymized, since those
    /// items already carry the span (`start`, `end`) and entity type of every
    /// transformed region. The two slices must be the same length. Work is
    /// dispatched across the `rayon` thread pool; the returned vector is in
    /// input order regardless of completion order.
    ///
    /// This is the parallel batch deanonymizer Presidio lacks entirely.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if `texts.len() != operator_results.len()`.
    /// In [`strict`](Self::strict) mode, also returns the **first** per-item
    /// error in input order (an unknown operator, an invalid config, a failed
    /// tag check, or an out-of-bounds span), discarding the rest of the batch.
    /// In the default lenient mode, per-item errors are not returned here —
    /// they are recorded in the corresponding result's `items` (see the
    /// type-level error-semantics note).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use octarine::anonymize::{BatchDeanonymizeEngine, OperatorResult};
    ///
    /// // A text whose only "anonymized" span is an unknown operator: lenient
    /// // mode keeps the input and records the error in `items`.
    /// let batch = BatchDeanonymizeEngine::new();
    /// let texts = ["nothing to reverse"];
    /// let items = vec![vec![]]; // no spans → input returned unchanged
    /// let out = batch.deanonymize_list(&texts, &items, &HashMap::new())?;
    /// assert_eq!(out.first().and_then(|r| r.text.as_deref()), Some("nothing to reverse"));
    /// # Ok::<(), octarine_problem::Problem>(())
    /// ```
    pub fn deanonymize_list(
        &self,
        texts: &[&str],
        operator_results: &[Vec<OperatorResult>],
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<Vec<EngineResult>> {
        let start = std::time::Instant::now();
        let outcome = self.deanonymize_list_inner(texts, operator_results, operators);

        if self.emit_events {
            record(
                metric_names::batch_deanonymize_duration_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            increment(metric_names::batch_deanonymize_total());
            match &outcome {
                Ok(out) => {
                    increment_by(
                        metric_names::batch_deanonymize_items_total(),
                        out.len() as u64,
                    );
                    let failed = out.iter().filter(|r| is_error_result(r)).count();
                    if failed > 0 {
                        observe::warn(
                            "batch_deanonymize",
                            format!(
                                "deanonymized {} text(s) in parallel; {failed} item(s) failed and were left anonymized",
                                out.len()
                            ),
                        );
                    } else {
                        observe::debug(
                            "batch_deanonymize",
                            format!("deanonymized {} text(s) in parallel", out.len()),
                        );
                    }
                }
                Err(_) => observe::warn("batch_deanonymize", "batch deanonymize failed"),
            }
        }

        outcome
    }

    /// The un-instrumented parallel core of
    /// [`deanonymize_list`](Self::deanonymize_list).
    ///
    /// Validates the length invariant and fans the items across the `rayon`
    /// thread pool, emitting no metrics or events. Used directly by the
    /// recursive [`deanonymize_dict`](Self::deanonymize_dict) traversal so that a
    /// dict call emits one aggregate metric rather than one per nested array.
    fn deanonymize_list_inner(
        &self,
        texts: &[&str],
        operator_results: &[Vec<OperatorResult>],
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<Vec<EngineResult>> {
        if texts.len() != operator_results.len() {
            return Err(Problem::Validation(format!(
                "batch deanonymize_list length mismatch: {} texts but {} result lists",
                texts.len(),
                operator_results.len()
            )));
        }

        texts
            .par_iter()
            .zip(operator_results.par_iter())
            .map(|(text, items)| self.deanonymize_one(text, items, operators))
            .collect()
    }

    /// Reverses a single `text` from its `OperatorResult` spans.
    ///
    /// The spans are converted to [`RecognizerResult`]s (score `1.0`, the
    /// canonical certainty for a region the anonymizer itself produced) and fed
    /// to the sync engine, whose configured reverse operators rewrite each span.
    /// In lenient mode a failure is folded into a passthrough result via
    /// [`error_result`] so the parallel `collect` never short-circuits; in strict
    /// mode the error propagates and fails the batch.
    ///
    /// Span validation (`RecognizerResult::new`, which rejects `start > end`) is
    /// folded into the same lenient/strict policy as operator failures: an
    /// `OperatorResult` has public fields and may arrive from deserialized or
    /// tampered JSON, so an inverted span must not abort a lenient batch.
    fn deanonymize_one(
        &self,
        text: &str,
        items: &[OperatorResult],
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<EngineResult> {
        let results: Result<Vec<RecognizerResult>> = items
            .iter()
            .map(|item| RecognizerResult::new(item.entity_type.clone(), item.start, item.end, 1.0))
            .collect();

        let outcome = results.and_then(|results| self.engine.anonymize(text, results, operators));

        match outcome {
            Ok(result) => Ok(result),
            Err(problem) if self.strict => Err(problem),
            // Lenient: keep the still-anonymized input and record the error.
            // Covers both span-validation and operator failures.
            Err(problem) => Ok(error_result(text, &problem)),
        }
    }

    /// Deanonymizes a nested [`serde_json::Value`], recursing into objects and
    /// arrays and dispatching string-array values to
    /// [`deanonymize_list`](Self::deanonymize_list).
    ///
    /// `operator_results_by_path` maps a JSON **path** to the operator items for
    /// the string at that path, using the same dot-separated path encoding as
    /// [`BatchAnonymizerEngine::anonymize_dict`] (object keys join with `.`,
    /// array elements use their numeric index, the root path is `""`). The same
    /// path-ambiguity caller contract applies — see that method for the full
    /// note.
    ///
    /// Strings with no entry in `operator_results_by_path` are returned
    /// unchanged. Non-string scalars always pass through unchanged. Object key
    /// sets and array lengths are preserved. Per-item error semantics match
    /// [`deanonymize_list`](Self::deanonymize_list): a failed reverse leaves the
    /// anonymized string in place under lenient mode, or fails the call under
    /// [`strict`](Self::strict).
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] for an internally-inconsistent traversal,
    /// and (in strict mode only) the first reverse error encountered.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use serde_json::json;
    /// use octarine::anonymize::{BatchDeanonymizeEngine, OperatorResult};
    ///
    /// // No spans for any path → the structure round-trips unchanged.
    /// let batch = BatchDeanonymizeEngine::new();
    /// let input = json!({ "user": { "note": "hello" }, "age": 42 });
    /// let out = batch.deanonymize_dict(&input, &HashMap::new(), &HashMap::new())?;
    /// assert_eq!(out, input);
    /// # Ok::<(), octarine_problem::Problem>(())
    /// ```
    pub fn deanonymize_dict(
        &self,
        value: &Value,
        operator_results_by_path: &HashMap<String, Vec<OperatorResult>>,
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<Value> {
        let start = std::time::Instant::now();
        let outcome = self.deanonymize_value(value, "", operator_results_by_path, operators);

        if self.emit_events {
            record(
                metric_names::batch_deanonymize_duration_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            increment(metric_names::batch_deanonymize_total());
            match &outcome {
                Ok(_) => observe::debug("batch_deanonymize", "deanonymized nested dict"),
                Err(_) => observe::warn("batch_deanonymize", "batch deanonymize_dict failed"),
            }
        }

        outcome
    }

    /// Recursively deanonymizes one JSON `value` at `path`.
    ///
    /// Mirrors [`BatchAnonymizerEngine::anonymize_value`]: objects and non-string
    /// arrays recurse element-wise; an all-string array dispatches to the
    /// un-instrumented `deanonymize_list_inner` so its elements reverse in
    /// parallel without double-emitting metrics; a string is reversed when
    /// `operator_results_by_path` has an entry for `path`; every other scalar
    /// passes through unchanged.
    fn deanonymize_value(
        &self,
        value: &Value,
        path: &str,
        operator_results_by_path: &HashMap<String, Vec<OperatorResult>>,
        operators: &HashMap<String, OperatorConfig>,
    ) -> Result<Value> {
        match value {
            Value::Object(map) => {
                let mut out = Map::with_capacity(map.len());
                for (key, child) in map {
                    let child_path = join_path(path, key);
                    out.insert(
                        key.clone(),
                        self.deanonymize_value(
                            child,
                            &child_path,
                            operator_results_by_path,
                            operators,
                        )?,
                    );
                }
                Ok(Value::Object(out))
            }
            Value::Array(items) => {
                // Fast path: an array of all strings is a batch — reverse its
                // elements in parallel through `deanonymize_list_inner`.
                if !items.is_empty() && items.iter().all(Value::is_string) {
                    let texts: Vec<&str> = items
                        .iter()
                        .map(|v| v.as_str().unwrap_or_default())
                        .collect();
                    let per_item: Vec<Vec<OperatorResult>> = (0..items.len())
                        .map(|i| {
                            let elem_path = join_index(path, i);
                            operator_results_by_path
                                .get(&elem_path)
                                .cloned()
                                .unwrap_or_default()
                        })
                        .collect();
                    let reversed = self.deanonymize_list_inner(&texts, &per_item, operators)?;
                    let out: Vec<Value> = reversed
                        .into_iter()
                        .map(|r| Value::String(r.text.unwrap_or_default()))
                        .collect();
                    return Ok(Value::Array(out));
                }
                // Mixed/non-string array: recurse element-wise by index.
                let mut out = Vec::with_capacity(items.len());
                for (i, child) in items.iter().enumerate() {
                    let child_path = join_index(path, i);
                    out.push(self.deanonymize_value(
                        child,
                        &child_path,
                        operator_results_by_path,
                        operators,
                    )?);
                }
                Ok(Value::Array(out))
            }
            Value::String(s) => match operator_results_by_path.get(path) {
                Some(items) => {
                    let result = self.deanonymize_one(s, items, operators)?;
                    Ok(Value::String(result.text.unwrap_or_default()))
                }
                // No spans for this path: pass the string through unchanged.
                None => Ok(value.clone()),
            },
            // Type passthrough: numbers, booleans, and null carry no PII.
            Value::Number(_) | Value::Bool(_) | Value::Null => Ok(value.clone()),
        }
    }
}

/// Builds a passthrough [`EngineResult`] for a lenient-mode item that failed to
/// reverse: the still-anonymized `text` is preserved and a single
/// `DEANONYMIZE_ERROR` [`OperatorResult`] records `problem` so the error is
/// collected in `items` rather than dropped.
fn error_result(text: &str, problem: &Problem) -> EngineResult {
    let mut result = EngineResult::new();
    result.set_text(text);
    // `0..0` is always a valid (zero-width) span, so this construction never
    // fails; fall back to an empty item rather than panicking if it ever does.
    if let Ok(item) = OperatorResult::new(
        DEANONYMIZE_ERROR_ENTITY,
        0,
        0,
        Some(problem.to_string()),
        Some("error".to_string()),
    ) {
        result.add_item(item);
    }
    result
}

/// Returns `true` if `result` is a lenient-mode per-item failure marker
/// produced by [`error_result`].
fn is_error_result(result: &EngineResult) -> bool {
    result
        .items
        .iter()
        .any(|item| item.entity_type == DEANONYMIZE_ERROR_ENTITY)
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

    use base64::Engine as _;
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

    // --- Batch deanonymize -----------------------------------------------------

    /// 32 zero bytes, base64url-no-pad — the shared test key for the round-trip
    /// `encrypt` → `decrypt` deanonymize tests.
    const KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn encrypt_ops(entity: &str) -> HashMap<String, OperatorConfig> {
        let mut params = HashMap::new();
        params.insert("key".to_string(), json!(KEY_B64));
        let mut ops = HashMap::new();
        ops.insert(
            entity.to_string(),
            OperatorConfig::with_params("encrypt", params).expect("cfg"),
        );
        ops
    }

    fn decrypt_ops(entity: &str) -> HashMap<String, OperatorConfig> {
        let mut params = HashMap::new();
        params.insert("key".to_string(), json!(KEY_B64));
        let mut ops = HashMap::new();
        ops.insert(
            entity.to_string(),
            OperatorConfig::with_params("decrypt", params).expect("cfg"),
        );
        ops
    }

    #[test]
    fn deanonymize_empty_list_returns_empty() {
        let batch = BatchDeanonymizeEngine::new();
        let out = batch
            .deanonymize_list(&[], &[], &HashMap::new())
            .expect("deanonymize_list");
        assert!(out.is_empty());
    }

    #[test]
    fn deanonymize_length_mismatch_errors() {
        let batch = BatchDeanonymizeEngine::new();
        let texts = ["a", "b"];
        let items = vec![vec![]]; // only one list for two texts
        let err = batch.deanonymize_list(&texts, &items, &HashMap::new());
        assert!(err.is_err());
    }

    #[test]
    fn deanonymize_list_round_trips_encrypt_decrypt() {
        // Anonymize a batch with `encrypt`, then feed the produced text + items
        // straight back into `deanonymize_list` with `decrypt`: originals return.
        let anon = BatchAnonymizerEngine::new();
        let texts = ["SSN 123-45-6789.", "SSN 987-65-4321."];
        let results = vec![vec![rr("US_SSN", 4, 15)], vec![rr("US_SSN", 4, 15)]];
        let sealed = anon
            .anonymize_list(&texts, &results, &encrypt_ops("US_SSN"))
            .expect("anonymize_list");

        let sealed_texts: Vec<&str> = sealed
            .iter()
            .map(|r| r.text.as_deref().expect("text"))
            .collect();
        let items: Vec<Vec<OperatorResult>> = sealed.iter().map(|r| r.items.clone()).collect();

        let restored = BatchDeanonymizeEngine::new()
            .deanonymize_list(&sealed_texts, &items, &decrypt_ops("US_SSN"))
            .expect("deanonymize_list");

        assert_eq!(restored.len(), 2);
        assert_eq!(
            restored.first().expect("0").text.as_deref(),
            Some("SSN 123-45-6789.")
        );
        assert_eq!(
            restored.get(1).expect("1").text.as_deref(),
            Some("SSN 987-65-4321.")
        );
    }

    #[test]
    fn deanonymize_list_1000_items_preserves_order() {
        // Encrypt 1000 uniquely-tagged texts, then decrypt and assert output[i]
        // still corresponds to input[i] after the parallel reverse.
        let anon = BatchAnonymizerEngine::new();
        let texts: Vec<String> = (0..1000)
            .map(|i| format!("user{i} ssn 123-45-6789"))
            .collect();
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let results: Vec<Vec<RecognizerResult>> = texts
            .iter()
            .map(|t| {
                let start = t.find("123-45-6789").expect("ssn present");
                vec![rr("US_SSN", start, start + "123-45-6789".len())]
            })
            .collect();
        let sealed = anon
            .anonymize_list(&refs, &results, &encrypt_ops("US_SSN"))
            .expect("anonymize_list");

        let sealed_texts: Vec<&str> = sealed
            .iter()
            .map(|r| r.text.as_deref().expect("text"))
            .collect();
        let items: Vec<Vec<OperatorResult>> = sealed.iter().map(|r| r.items.clone()).collect();

        let restored = BatchDeanonymizeEngine::new()
            .deanonymize_list(&sealed_texts, &items, &decrypt_ops("US_SSN"))
            .expect("deanonymize_list");

        assert_eq!(restored.len(), 1000);
        for (i, result) in restored.iter().enumerate() {
            assert_eq!(
                result.text.as_deref().expect("text"),
                format!("user{i} ssn 123-45-6789")
            );
        }
    }

    #[test]
    fn deanonymize_lenient_collects_per_item_error() {
        // Genuinely mixed batch: item 0 has an encrypted span that a wrong-key
        // decrypt fails; item 1 has no spans and reverses trivially. Default
        // lenient mode must keep item 0 anonymized with the error recorded in
        // its `items`, AND still return item 1 reversed — proving one failure
        // does not abort the batch.
        let anon = BatchAnonymizerEngine::new();
        let sealed = anon
            .anonymize_list(
                &["SSN 123-45-6789."],
                &[vec![rr("US_SSN", 4, 15)]],
                &encrypt_ops("US_SSN"),
            )
            .expect("anonymize_list");
        let sealed_text = sealed.first().expect("0").text.clone().expect("text");
        let sealed_items = sealed.first().expect("0").items.clone();

        // Batch: [encrypted text + its span], [plain text + no spans].
        let texts = [sealed_text.as_str(), "nothing here"];
        let items = vec![sealed_items, vec![]];

        // Wrong key → item 0's decrypt fails the tag check.
        let other = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let mut wrong_params = HashMap::new();
        wrong_params.insert("key".to_string(), json!(other));
        let mut wrong = HashMap::new();
        wrong.insert(
            "US_SSN".to_string(),
            OperatorConfig::with_params("decrypt", wrong_params).expect("cfg"),
        );

        let restored = BatchDeanonymizeEngine::new()
            .deanonymize_list(&texts, &items, &wrong)
            .expect("lenient batch does not abort");

        assert_eq!(restored.len(), 2);
        // Item 0: failed → still anonymized, error captured in items.
        let first = restored.first().expect("0");
        assert_eq!(first.text.as_deref(), Some(sealed_text.as_str()));
        assert!(is_error_result(first));
        assert_eq!(
            first.items.first().expect("err item").entity_type,
            DEANONYMIZE_ERROR_ENTITY
        );
        // Item 1: succeeded → passthrough plain text, no error marker.
        let second = restored.get(1).expect("1");
        assert_eq!(second.text.as_deref(), Some("nothing here"));
        assert!(!is_error_result(second));
    }

    #[test]
    fn deanonymize_lenient_does_not_abort_on_invalid_span() {
        // An inverted span (start > end) fails RecognizerResult::new. Such an
        // item can arrive from deserialized/tampered JSON (OperatorResult has
        // public fields), so lenient mode must fold the validation failure into
        // an error_result rather than aborting the batch — regression guard for
        // the span-validation-bypasses-lenient-mode bug.
        let batch = BatchDeanonymizeEngine::new();
        // OperatorResult rejects start > end at construction, so build the
        // inverted span by mutating the public fields after a valid construction.
        let mut bad = OperatorResult::new("X", 0, 0, None, None).expect("op");
        bad.start = 99;
        bad.end = 2;
        let texts = ["some text", "second"];
        let items = vec![vec![bad], vec![]];

        let out = batch
            .deanonymize_list(&texts, &items, &HashMap::new())
            .expect("lenient batch must not abort on invalid span");

        assert_eq!(out.len(), 2);
        // Item 0: invalid span → left unchanged, error recorded.
        let first = out.first().expect("0");
        assert_eq!(first.text.as_deref(), Some("some text"));
        assert!(is_error_result(first));
        // Item 1: trivially reverses.
        assert_eq!(out.get(1).expect("1").text.as_deref(), Some("second"));
        assert!(!is_error_result(out.get(1).expect("1")));
    }

    #[test]
    fn deanonymize_strict_fails_on_invalid_span() {
        // Symmetric to the lenient case: strict mode surfaces the span-validation
        // failure as an error.
        let batch = BatchDeanonymizeEngine::new().strict();
        let mut bad = OperatorResult::new("X", 0, 0, None, None).expect("op");
        bad.start = 99;
        bad.end = 2;
        let err = batch.deanonymize_list(&["t"], &[vec![bad]], &HashMap::new());
        assert!(err.is_err());
    }

    #[test]
    fn deanonymize_dict_lenient_keeps_failed_string_anonymized() {
        // Lenient dict traversal: a string value that fails to reverse (wrong
        // decrypt key) is left anonymized in place and the call still returns Ok,
        // mirroring the list-level lenient contract through deanonymize_value.
        let anon = BatchAnonymizerEngine::new();
        let input = json!({ "ssn": "123-45-6789", "note": "plain" });
        let mut by_path = HashMap::new();
        by_path.insert("ssn".to_string(), vec![rr("US_SSN", 0, 11)]);
        let sealed = anon
            .anonymize_dict(&input, &by_path, &encrypt_ops("US_SSN"))
            .expect("anonymize_dict");
        let sealed_ssn = value_at(&sealed, &["ssn"]).to_string();

        let mut rev = HashMap::new();
        rev.insert(
            "ssn".to_string(),
            vec![OperatorResult::new("US_SSN", 0, sealed_ssn.len(), None, None).expect("op")],
        );
        // Wrong key → the ssn decrypt fails; lenient mode keeps it anonymized.
        let other = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let mut wrong_params = HashMap::new();
        wrong_params.insert("key".to_string(), json!(other));
        let mut wrong = HashMap::new();
        wrong.insert(
            "US_SSN".to_string(),
            OperatorConfig::with_params("decrypt", wrong_params).expect("cfg"),
        );

        let out = BatchDeanonymizeEngine::new()
            .deanonymize_dict(&sealed, &rev, &wrong)
            .expect("lenient dict must not abort");
        // The ssn stays the sealed (anonymized) value; the plain note is intact.
        assert_eq!(value_at(&out, &["ssn"]), sealed_ssn);
        assert_eq!(value_at(&out, &["note"]), "plain");
    }

    #[test]
    fn deanonymize_strict_fails_whole_batch_on_error() {
        let anon = BatchAnonymizerEngine::new();
        let texts = ["SSN 123-45-6789."];
        let results = vec![vec![rr("US_SSN", 4, 15)]];
        let sealed = anon
            .anonymize_list(&texts, &results, &encrypt_ops("US_SSN"))
            .expect("anonymize_list");
        let sealed_texts: Vec<&str> = sealed
            .iter()
            .map(|r| r.text.as_deref().expect("text"))
            .collect();
        let items: Vec<Vec<OperatorResult>> = sealed.iter().map(|r| r.items.clone()).collect();

        let other = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let mut wrong_params = HashMap::new();
        wrong_params.insert("key".to_string(), json!(other));
        let mut wrong = HashMap::new();
        wrong.insert(
            "US_SSN".to_string(),
            OperatorConfig::with_params("decrypt", wrong_params).expect("cfg"),
        );

        let err =
            BatchDeanonymizeEngine::new()
                .strict()
                .deanonymize_list(&sealed_texts, &items, &wrong);
        assert!(err.is_err());
    }

    #[test]
    fn deanonymize_no_spans_returns_input_unchanged() {
        let batch = BatchDeanonymizeEngine::new();
        let texts = ["already plain"];
        let items = vec![vec![]];
        let out = batch
            .deanonymize_list(&texts, &items, &HashMap::new())
            .expect("deanonymize_list");
        assert_eq!(
            out.first().expect("0").text.as_deref(),
            Some("already plain")
        );
    }

    #[test]
    fn deanonymize_dict_round_trips_nested_structure() {
        // Anonymize a nested dict with encrypt, capture the produced items by
        // path, then deanonymize_dict back to the original structure.
        let anon = BatchAnonymizerEngine::new();
        let input = json!({ "users": [{ "ssn": "123-45-6789" }, { "ssn": "987-65-4321" }] });
        let mut by_path = HashMap::new();
        by_path.insert("users.0.ssn".to_string(), vec![rr("US_SSN", 0, 11)]);
        by_path.insert("users.1.ssn".to_string(), vec![rr("US_SSN", 0, 11)]);
        let sealed = anon
            .anonymize_dict(&input, &by_path, &encrypt_ops("US_SSN"))
            .expect("anonymize_dict");

        // The sealed strings differ from the originals.
        assert_ne!(sealed, input);

        // Build the reverse path map: each anonymized string is one whole span.
        let mut rev_by_path = HashMap::new();
        for (path, sealed_text) in [
            ("users.0.ssn", value_at(&sealed, &["users", "0", "ssn"])),
            ("users.1.ssn", value_at(&sealed, &["users", "1", "ssn"])),
        ] {
            rev_by_path.insert(
                path.to_string(),
                vec![OperatorResult::new("US_SSN", 0, sealed_text.len(), None, None).expect("op")],
            );
        }

        let restored = BatchDeanonymizeEngine::new()
            .deanonymize_dict(&sealed, &rev_by_path, &decrypt_ops("US_SSN"))
            .expect("deanonymize_dict");

        assert_eq!(restored, input);
    }

    #[test]
    fn deanonymize_dict_type_passthrough() {
        let batch = BatchDeanonymizeEngine::new();
        let input = json!({ "name": "Bob", "age": 42, "active": true, "x": null, "score": 3.5 });
        let out = batch
            .deanonymize_dict(&input, &HashMap::new(), &HashMap::new())
            .expect("deanonymize_dict");
        // Nothing to reverse — every scalar passes through unchanged.
        assert_eq!(out, input);
    }

    #[test]
    fn deanonymize_dict_string_array_fast_path() {
        let anon = BatchAnonymizerEngine::new();
        let input = json!({ "tags": ["123-45-6789", "987-65-4321"] });
        let mut by_path = HashMap::new();
        by_path.insert("tags.0".to_string(), vec![rr("US_SSN", 0, 11)]);
        by_path.insert("tags.1".to_string(), vec![rr("US_SSN", 0, 11)]);
        let sealed = anon
            .anonymize_dict(&input, &by_path, &encrypt_ops("US_SSN"))
            .expect("anonymize_dict");

        let mut rev = HashMap::new();
        for (i, key) in ["tags.0", "tags.1"].iter().enumerate() {
            let s = value_at(&sealed, &["tags", &i.to_string()]);
            rev.insert(
                (*key).to_string(),
                vec![OperatorResult::new("US_SSN", 0, s.len(), None, None).expect("op")],
            );
        }

        let restored = BatchDeanonymizeEngine::new()
            .deanonymize_dict(&sealed, &rev, &decrypt_ops("US_SSN"))
            .expect("deanonymize_dict");
        assert_eq!(restored, input);
    }

    #[test]
    fn deanonymize_dict_mixed_array_recurses_by_index() {
        // A mixed array (string + number) takes the element-wise recursion path,
        // not the all-string fast path; the number passes through.
        let anon = BatchAnonymizerEngine::new();
        let input = json!({ "vals": ["123-45-6789", 7] });
        let mut by_path = HashMap::new();
        by_path.insert("vals.0".to_string(), vec![rr("US_SSN", 0, 11)]);
        let sealed = anon
            .anonymize_dict(&input, &by_path, &encrypt_ops("US_SSN"))
            .expect("anonymize_dict");

        let s = value_at(&sealed, &["vals", "0"]);
        let mut rev = HashMap::new();
        rev.insert(
            "vals.0".to_string(),
            vec![OperatorResult::new("US_SSN", 0, s.len(), None, None).expect("op")],
        );
        let restored = BatchDeanonymizeEngine::new()
            .deanonymize_dict(&sealed, &rev, &decrypt_ops("US_SSN"))
            .expect("deanonymize_dict");
        assert_eq!(restored, json!({ "vals": ["123-45-6789", 7] }));
    }

    #[test]
    fn deanonymize_dict_empty_array_unchanged() {
        let batch = BatchDeanonymizeEngine::new();
        let input = json!({ "tags": [] });
        let out = batch
            .deanonymize_dict(&input, &HashMap::new(), &HashMap::new())
            .expect("deanonymize_dict");
        assert_eq!(out, json!({ "tags": [] }));
    }

    #[test]
    fn deanonymize_dict_strict_error_propagates() {
        // A string span whose start..end is out of bounds makes the inner reverse
        // fail; strict mode surfaces it rather than swallowing it.
        let batch = BatchDeanonymizeEngine::new().strict();
        let input = json!({ "note": "hi" });
        let mut by_path = HashMap::new();
        by_path.insert(
            "note".to_string(),
            vec![OperatorResult::new("X", 2, 99, None, None).expect("op")],
        );
        let err = batch.deanonymize_dict(&input, &by_path, &HashMap::new());
        assert!(err.is_err());
    }

    #[test]
    fn deanonymize_silent_still_transforms() {
        // Covers the deanonymize_list branch under emit_events = false.
        let anon = BatchAnonymizerEngine::new();
        let texts = ["SSN 123-45-6789."];
        let results = vec![vec![rr("US_SSN", 4, 15)]];
        let sealed = anon
            .anonymize_list(&texts, &results, &encrypt_ops("US_SSN"))
            .expect("anonymize_list");
        let sealed_texts: Vec<&str> = sealed
            .iter()
            .map(|r| r.text.as_deref().expect("text"))
            .collect();
        let items: Vec<Vec<OperatorResult>> = sealed.iter().map(|r| r.items.clone()).collect();

        let restored = BatchDeanonymizeEngine::new()
            .silent()
            .deanonymize_list(&sealed_texts, &items, &decrypt_ops("US_SSN"))
            .expect("deanonymize_list");
        assert_eq!(
            restored.first().expect("0").text.as_deref(),
            Some("SSN 123-45-6789.")
        );
    }

    #[test]
    fn deanonymize_default_and_debug_impls() {
        let batch = BatchDeanonymizeEngine::default();
        let rendered = format!("{batch:?}");
        assert!(rendered.contains("BatchDeanonymizeEngine"));
        assert!(rendered.contains("strict"));
    }

    #[test]
    fn deanonymize_with_engine_uses_custom_engine() {
        use crate::anonymize::AnonymizerEngine;
        let engine = AnonymizerEngine::new().silent();
        let batch = BatchDeanonymizeEngine::with_engine(engine);
        let texts = ["plain"];
        let items = vec![vec![]];
        let out = batch
            .deanonymize_list(&texts, &items, &HashMap::new())
            .expect("deanonymize_list");
        assert_eq!(out.first().expect("0").text.as_deref(), Some("plain"));
    }

    /// Reads the string at a dotted key path out of a `serde_json::Value`,
    /// for building reverse span maps in the dict tests.
    fn value_at<'a>(value: &'a Value, path: &[&str]) -> &'a str {
        let mut cur = value;
        for key in path {
            cur = if let Ok(idx) = key.parse::<usize>() {
                cur.get(idx).expect("index in bounds")
            } else {
                cur.get(*key).expect("key present")
            };
        }
        cur.as_str().expect("string value")
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
