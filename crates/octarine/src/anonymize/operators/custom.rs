//! Custom operator — a pluggable, user-supplied transformation closure.
//!
//! `Custom` lets a caller plug in their own per-span transform
//! (`Fn(&str) -> Result<String>`) for entity types their organization handles
//! specially — format-preserving customer-ID transforms, stateful
//! pseudonymization, token-vault lookups — without forking octarine. The
//! closure lives on the operator itself and is registered with an engine via
//! [`AnonymizerEngine::with_operator`](crate::anonymize::AnonymizerEngine::with_operator).
//!
//! # No-probe-call discipline (the headline guarantee)
//!
//! [`validate`](Operator::validate) **never invokes the closure.** It only
//! checks that a closure is present. This is a deliberate, structural
//! guarantee, not a convention: the engine calls `validate` once per span
//! before any output is built, and `validate` is handed only an
//! [`OperatorConfig`] — never the closure — so it *cannot* call it even by
//! accident.
//!
//! Presidio learned this the hard way. Its `Custom.validate()` probe-called the
//! lambda with a dummy string ([Presidio issue #2024]); for stateful closures
//! (counters, vault references, `Arc<Mutex<…>>` maps) that probe corrupted
//! state — the closure ran one extra time, off-by-one against the real spans.
//! Octarine makes the corruption impossible by construction: a closure that
//! transforms N spans is invoked exactly N times, never N+1.
//!
//! [Presidio issue #2024]: https://github.com/microsoft/presidio/issues/2024

use std::sync::Arc;

use octarine_problem::{Problem, Result};

use super::super::operator::Operator;
use super::super::{OperatorConfig, OperatorType};

/// A user-supplied, fallible per-span transform.
///
/// `Send + Sync` so an operator holding one can be shared across threads (the
/// [`Operator`] trait requires it). Wrapped in [`Arc`] so the operator is cheap
/// to clone and the same closure can be shared.
type CustomFn = Arc<dyn Fn(&str) -> Result<String> + Send + Sync>;

/// Applies a caller-supplied closure to each matched span.
///
/// Construct with [`Custom::new`] for the anonymize direction or
/// [`Custom::deanonymizer`] for the reverse direction, then register the
/// operator with an engine. An operator built via [`Default`] carries **no**
/// closure and deliberately fails [`validate`](Operator::validate) — there is
/// nothing to apply.
///
/// # No-probe-call discipline
///
/// [`validate`](Operator::validate) checks only that a closure is present; it
/// never invokes it. Presidio's `Custom.validate()` probe-called the lambda
/// with a dummy string ([Presidio issue #2024]), corrupting stateful closures
/// (counters, vault references) by running them one extra time. Octarine makes
/// that impossible: `validate` is handed only an [`OperatorConfig`], never the
/// closure, so a closure transforming N spans is invoked exactly N times.
///
/// [Presidio issue #2024]: https://github.com/microsoft/presidio/issues/2024
///
/// # Examples
///
/// Stateful pseudonymization: a closure captures an
/// `Arc<Mutex<HashMap<String, String>>>` vault and maps each distinct original
/// to a stable token, so the same value anonymizes to the same token every
/// time it appears.
///
/// ```
/// use std::collections::HashMap;
/// use std::sync::{Arc, Mutex};
///
/// use octarine::anonymize::{AnonymizerEngine, Custom, OperatorConfig, RecognizerResult};
/// use octarine_problem::Problem;
///
/// // Shared vault: original value -> stable token. A stateful closure like
/// // this is exactly what Presidio's probe-call corrupted.
/// let vault: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
///
/// let pseudonymize = Custom::new(move |original: &str| {
///     let mut map = vault
///         .lock()
///         .map_err(|_| Problem::Validation("vault mutex poisoned".to_string()))?;
///     let next = map.len();
///     let token = map
///         .entry(original.to_string())
///         .or_insert_with(|| format!("<PERSON_{next}>"))
///         .clone();
///     Ok(token)
/// });
///
/// let engine = AnonymizerEngine::new().with_operator(Box::new(pseudonymize));
///
/// let mut operators = HashMap::new();
/// operators.insert("PERSON".to_string(), OperatorConfig::new("custom")?);
///
/// // "Bob" appears twice; both occurrences map to the same stable token.
/// let text = "Bob met Bob";
/// let results = vec![
///     RecognizerResult::new("PERSON", 0, 3, 0.9)?,
///     RecognizerResult::new("PERSON", 8, 11, 0.9)?,
/// ];
/// let out = engine.anonymize(text, results, &operators)?;
/// assert_eq!(out.text.as_deref(), Some("<PERSON_0> met <PERSON_0>"));
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
pub struct Custom {
    /// The transform to apply, or `None` for an unconfigured operator that
    /// fails validation.
    closure: Option<CustomFn>,
    /// Whether this operator anonymizes or deanonymizes — controls both
    /// [`operator_name`](Operator::operator_name) and
    /// [`operator_type`](Operator::operator_type).
    operator_type: OperatorType,
}

impl Custom {
    /// Creates an anonymize-direction `Custom` operator wrapping `closure`.
    ///
    /// Registered under the name `"custom"`.
    pub fn new<F>(closure: F) -> Self
    where
        F: Fn(&str) -> Result<String> + Send + Sync + 'static,
    {
        Self {
            closure: Some(Arc::new(closure)),
            operator_type: OperatorType::Anonymize,
        }
    }

    /// Creates a deanonymize-direction `Custom` operator wrapping `closure`.
    ///
    /// Registered under the name `"custom_deanonymize"` so it can coexist with
    /// an anonymize-direction `Custom` in the same engine registry. This is the
    /// companion path for reversible tokenization without AES — the reverse
    /// closure looks each token back up in the same shared vault.
    pub fn deanonymizer<F>(closure: F) -> Self
    where
        F: Fn(&str) -> Result<String> + Send + Sync + 'static,
    {
        Self {
            closure: Some(Arc::new(closure)),
            operator_type: OperatorType::Deanonymize,
        }
    }
}

impl Default for Custom {
    /// An unconfigured operator (no closure). It fails
    /// [`validate`](Operator::validate); use [`Custom::new`] or
    /// [`Custom::deanonymizer`] to supply a closure.
    fn default() -> Self {
        Self {
            closure: None,
            operator_type: OperatorType::Anonymize,
        }
    }
}

impl std::fmt::Debug for Custom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The closure is not `Debug`; report only whether one is configured.
        f.debug_struct("Custom")
            .field("configured", &self.closure.is_some())
            .field("operator_type", &self.operator_type)
            .finish()
    }
}

impl Operator for Custom {
    fn operate(&self, text: &str, _entity_type: &str, _config: &OperatorConfig) -> Result<String> {
        match &self.closure {
            // Propagate the closure's own error as a `Problem` — never panic
            // the engine on a misbehaving closure.
            Some(closure) => closure(text),
            None => Err(Problem::Validation(
                "custom operator has no closure configured".to_string(),
            )),
        }
    }

    /// Checks that a closure is present — and **never invokes it**.
    ///
    /// See [`Custom`] for the no-probe-call rationale (Presidio #2024). The
    /// `config` is intentionally unused: validity depends only on the operator
    /// holding a closure, not on any parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if no closure was configured (e.g. a
    /// [`Custom::default`] operator).
    fn validate(&self, _config: &OperatorConfig) -> Result<()> {
        if self.closure.is_some() {
            Ok(())
        } else {
            Err(Problem::Validation(
                "custom operator requires a closure; none configured".to_string(),
            ))
        }
    }

    fn operator_name(&self) -> &'static str {
        match self.operator_type {
            OperatorType::Anonymize => "custom",
            OperatorType::Deanonymize => "custom_deanonymize",
        }
    }

    fn operator_type(&self) -> OperatorType {
        self.operator_type
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::anonymize::{AnonymizerEngine, RecognizerResult};

    fn rr(entity: &str, start: usize, end: usize) -> RecognizerResult {
        RecognizerResult::new(entity, start, end, 0.9).expect("valid result")
    }

    fn custom_config() -> OperatorConfig {
        OperatorConfig::new("custom").expect("valid config")
    }

    /// The headline guarantee: a closure transforming N spans is invoked
    /// exactly N times, never N+1. A probe-call in `validate` (the Presidio
    /// #2024 bug) would push the count to N+1.
    #[test]
    fn closure_invoked_exactly_once_per_span_no_probe_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let op = Custom::new(move |original: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(original.to_uppercase())
        });

        let engine = AnonymizerEngine::new().with_operator(Box::new(op));
        let mut ops = HashMap::new();
        // Map every entity through the custom operator.
        ops.insert("DEFAULT".to_string(), custom_config());

        // Three spans in "aaa bbb ccc": [0,3) [4,7) [8,11).
        let results = vec![rr("X", 0, 3), rr("X", 4, 7), rr("X", 8, 11)];
        let out = engine
            .anonymize("aaa bbb ccc", results, &ops)
            .expect("anonymize");

        assert_eq!(out.text.as_deref(), Some("AAA BBB CCC"));
        // Exactly 3 — not 4. This is the no-probe-call proof.
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn validate_does_not_invoke_closure() {
        // A closure that panics if ever called. validate must not call it.
        let op = Custom::new(|_| -> Result<String> {
            panic!("closure must never be invoked during validate");
        });
        assert!(op.validate(&custom_config()).is_ok());
    }

    #[test]
    fn validate_rejects_unconfigured_operator() {
        let op = Custom::default();
        assert!(op.validate(&custom_config()).is_err());
    }

    #[test]
    fn unconfigured_operate_errors_without_panic() {
        let op = Custom::default();
        let err = op.operate("anything", "X", &custom_config());
        assert!(err.is_err());
    }

    #[test]
    fn closure_error_propagates_as_problem() {
        let op = Custom::new(|_: &str| -> Result<String> {
            Err(Problem::Validation("closure refused".to_string()))
        });
        let engine = AnonymizerEngine::new().with_operator(Box::new(op));
        let mut ops = HashMap::new();
        ops.insert("X".to_string(), custom_config());

        let err = engine.anonymize("abc", vec![rr("X", 0, 3)], &ops);
        assert!(err.is_err());
    }

    #[test]
    fn happy_path_through_engine_records_operator_name() {
        let op = Custom::new(|s: &str| Ok(format!("[{s}]")));
        let engine = AnonymizerEngine::new().with_operator(Box::new(op));
        let mut ops = HashMap::new();
        ops.insert("X".to_string(), custom_config());

        let out = engine
            .anonymize("a Bob z", vec![rr("X", 2, 5)], &ops)
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("a [Bob] z"));
        let item = out.items.first().expect("one item");
        assert_eq!(item.operator.as_deref(), Some("custom"));
    }

    #[test]
    fn deanonymizer_registration_path_applies_reverse_transform() {
        // Reverse closure registered under "custom_deanonymize".
        let op = Custom::deanonymizer(|token: &str| Ok(token.to_lowercase()));
        let engine = AnonymizerEngine::new().with_operator(Box::new(op));
        let mut ops = HashMap::new();
        ops.insert(
            "X".to_string(),
            OperatorConfig::new("custom_deanonymize").expect("valid config"),
        );

        let out = engine
            .anonymize("a TOKEN z", vec![rr("X", 2, 7)], &ops)
            .expect("deanonymize");
        assert_eq!(out.text.as_deref(), Some("a token z"));
        let item = out.items.first().expect("one item");
        assert_eq!(item.operator.as_deref(), Some("custom_deanonymize"));
    }

    #[test]
    fn closure_receives_exact_multibyte_slice() {
        let op = Custom::new(|original: &str| {
            assert_eq!(original, "héllo");
            Ok(format!("[{original}]"))
        });
        let engine = AnonymizerEngine::new().with_operator(Box::new(op));
        let mut ops = HashMap::new();
        ops.insert("X".to_string(), custom_config());

        // "héllo" is 6 bytes (é is 2). Span covers the whole word.
        let out = engine
            .anonymize("héllo", vec![rr("X", 0, 6)], &ops)
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("[héllo]"));
    }

    #[test]
    fn name_and_type_for_both_directions() {
        let anon = Custom::new(|s: &str| Ok(s.to_string()));
        assert_eq!(anon.operator_name(), "custom");
        assert_eq!(anon.operator_type(), OperatorType::Anonymize);

        let deanon = Custom::deanonymizer(|s: &str| Ok(s.to_string()));
        assert_eq!(deanon.operator_name(), "custom_deanonymize");
        assert_eq!(deanon.operator_type(), OperatorType::Deanonymize);
    }

    #[test]
    fn debug_reports_configured_flag() {
        let configured = format!("{:?}", Custom::new(|s: &str| Ok(s.to_string())));
        assert!(configured.contains("configured: true"));
        let unconfigured = format!("{:?}", Custom::default());
        assert!(unconfigured.contains("configured: false"));
    }
}
