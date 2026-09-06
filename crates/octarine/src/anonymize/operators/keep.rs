//! Keep operators — no-op transforms that leave a span untouched while still
//! recording that it was seen.
//!
//! Presidio's `keep` operator exists for the "scanned but intentionally
//! allowed" case: an entity the detector found and the policy chose **not** to
//! transform — an allow-listed corporate email domain, an internal hostname, a
//! customer reference the downstream system needs verbatim.
//!
//! The value is entirely in the audit trail. Skipping such an entity (by simply
//! not passing its span to the engine) and keeping it produce **identical
//! output text**, but they are very different compliance stories: a skipped
//! entity is indistinguishable from one the detector never found, while a kept
//! entity lands in [`EngineResult.items`](crate::anonymize::EngineResult) with
//! its type, offsets, and `operator: "keep"`. That record is what proves to a
//! SOC2 or HIPAA auditor that the scanner saw the PII and allowed it on
//! purpose.
//!
//! Both operators implement the synchronous
//! [`Operator`](crate::anonymize::Operator) trait — a no-op needs no
//! [`StateStore`](crate::anonymize::StateStore) access, so unlike the
//! [`InstanceCounter`](crate::anonymize::InstanceCounterAnonymizer) pair they
//! stay off the async path entirely.
//!
//! # Examples
//!
//! Allow-list one entity type while redacting the rest. The kept span is
//! unchanged in the text but still reported:
//!
//! ```
//! use std::collections::HashMap;
//! use octarine::anonymize::{AnonymizerEngine, OperatorConfig, RecognizerResult};
//!
//! let engine = AnonymizerEngine::new();
//! let text = "Contact dev@acme.com or call 555-0100";
//!
//! let mut ops = HashMap::new();
//! ops.insert("EMAIL".to_string(), OperatorConfig::new("keep")?);
//!
//! let results = vec![
//!     RecognizerResult::new("EMAIL", 8, 20, 0.9)?,
//!     RecognizerResult::new("PHONE", 29, 37, 0.9)?,
//! ];
//! let out = engine.anonymize(text, results, &ops)?;
//!
//! // The email survives verbatim; the phone is replaced.
//! assert_eq!(out.text.as_deref(), Some("Contact dev@acme.com or call <PHONE>"));
//!
//! // ...but the kept email is still on the record for the audit trail.
//! let kept = out.items.iter().find(|i| i.entity_type == "EMAIL").expect("kept item");
//! assert_eq!(kept.operator.as_deref(), Some("keep"));
//! assert_eq!(kept.text.as_deref(), Some("dev@acme.com"));
//! # Ok::<(), octarine_problem::Problem>(())
//! ```

use octarine_problem::Result;

use crate::anonymize::{Operator, OperatorConfig, OperatorType};

/// The operator name [`Keep`] registers under.
const KEEP_NAME: &str = "keep";

/// The operator name [`DeanonymizeKeep`] registers under.
///
/// Deliberately **distinct** from [`KEEP_NAME`] rather than shared. The engine
/// registry is keyed by name alone, so two operators sharing a name would mean
/// the second registration silently evicts the first. The
/// [`Custom`](crate::anonymize::Custom) / `custom_deanonymize` pair splits its
/// names for the same reason; only
/// [`InstanceCounter`](crate::anonymize::InstanceCounterAnonymizer) shares one,
/// and it can because that pair is documented never to coexist in a single
/// engine. A keep has no such guarantee — one engine may legitimately want both
/// directions registered at once.
const KEEP_DEANONYMIZE_NAME: &str = "keep_deanonymize";

/// The no-op transform shared by [`Keep`] and [`DeanonymizeKeep`].
///
/// The two public operators differ **only** in
/// [`operator_name`](Operator::operator_name) and
/// [`operator_type`](Operator::operator_type); every byte of behavior lives
/// here, so the directions can never drift apart.
struct BaseKeep;

impl BaseKeep {
    /// Returns `text` unchanged.
    ///
    /// Infallible in practice, but returns [`Result`] to match the
    /// [`Operator::operate`] signature the callers forward to.
    fn operate(text: &str) -> Result<String> {
        Ok(text.to_string())
    }
}

/// Leaves a detected span unchanged while still reporting it in
/// [`EngineResult.items`](crate::anonymize::EngineResult).
///
/// Registered by default under `"keep"`. Route an entity type to it to
/// allow-list that type without losing the audit record.
///
/// Keeping a span and omitting it from the engine's input produce identical
/// output text, but only the kept span appears in
/// [`EngineResult.items`](crate::anonymize::EngineResult) — that record is the
/// audit evidence the operator exists for.
///
/// # Examples
///
/// ```
/// use octarine::anonymize::{Keep, Operator, OperatorConfig, OperatorType};
///
/// let op = Keep::new();
/// let config = OperatorConfig::new("keep")?;
/// assert_eq!(op.operate("dev@acme.com", "EMAIL", &config)?, "dev@acme.com");
/// assert_eq!(op.operator_type(), OperatorType::Anonymize);
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Keep;

impl Keep {
    /// Creates a `Keep` operator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Operator for Keep {
    fn operate(&self, text: &str, _entity_type: &str, _config: &OperatorConfig) -> Result<String> {
        BaseKeep::operate(text)
    }

    fn operator_name(&self) -> &'static str {
        KEEP_NAME
    }

    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
}

/// The deanonymize-direction counterpart of [`Keep`]: leaves a span unchanged
/// on the reverse pass while still reporting it.
///
/// Registered under `"keep_deanonymize"` and **opt-in** via
/// [`with_operator`](crate::anonymize::AnonymizerEngine::with_operator) — the
/// default registry carries only the anonymize-direction [`Keep`], mirroring
/// how the reverse [`Custom`](crate::anonymize::Custom) is opt-in.
///
/// Use it to record that a token span was examined during deanonymization and
/// deliberately left as-is — for instance a placeholder the reverse pass must
/// not rehydrate.
///
/// # Examples
///
/// ```
/// use octarine::anonymize::{DeanonymizeKeep, Operator, OperatorConfig, OperatorType};
///
/// let op = DeanonymizeKeep::new();
/// let config = OperatorConfig::new("keep_deanonymize")?;
/// assert_eq!(op.operate("<EMAIL_0>", "EMAIL", &config)?, "<EMAIL_0>");
/// assert_eq!(op.operator_type(), OperatorType::Deanonymize);
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct DeanonymizeKeep;

impl DeanonymizeKeep {
    /// Creates a `DeanonymizeKeep` operator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Operator for DeanonymizeKeep {
    fn operate(&self, text: &str, _entity_type: &str, _config: &OperatorConfig) -> Result<String> {
        BaseKeep::operate(text)
    }

    fn operator_name(&self) -> &'static str {
        KEEP_DEANONYMIZE_NAME
    }

    fn operator_type(&self) -> OperatorType {
        OperatorType::Deanonymize
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use std::collections::HashMap;

    use super::*;
    use crate::anonymize::{AnonymizerEngine, RecognizerResult};

    fn cfg(name: &str) -> OperatorConfig {
        OperatorConfig::new(name).expect("valid config")
    }

    fn rr(entity: &str, start: usize, end: usize) -> RecognizerResult {
        RecognizerResult::new(entity, start, end, 0.9).expect("valid result")
    }

    #[test]
    fn keep_returns_input_unchanged() {
        let op = Keep::new();
        assert_eq!(
            op.operate("dev@acme.com", "EMAIL", &cfg(KEEP_NAME))
                .expect("operate"),
            "dev@acme.com"
        );
        // Empty and multi-byte input are passed through just as literally.
        assert_eq!(op.operate("", "EMAIL", &cfg(KEEP_NAME)).expect("empty"), "");
        assert_eq!(
            op.operate("Zoë — 東京", "PERSON", &cfg(KEEP_NAME))
                .expect("unicode"),
            "Zoë — 東京"
        );
    }

    #[test]
    fn deanonymize_keep_returns_input_unchanged() {
        let op = DeanonymizeKeep::new();
        assert_eq!(
            op.operate("<EMAIL_0>", "EMAIL", &cfg(KEEP_DEANONYMIZE_NAME))
                .expect("operate"),
            "<EMAIL_0>"
        );
    }

    #[test]
    fn operator_identity() {
        // The pair shares one impl and differs only in name and direction.
        let keep = Keep::new();
        assert_eq!(keep.operator_name(), "keep");
        assert_eq!(keep.operator_type(), OperatorType::Anonymize);

        let deanon = DeanonymizeKeep::new();
        assert_eq!(deanon.operator_name(), "keep_deanonymize");
        assert_eq!(deanon.operator_type(), OperatorType::Deanonymize);

        // Distinct names are load-bearing: a shared name would let one evict
        // the other in the registry.
        assert_ne!(keep.operator_name(), deanon.operator_name());
    }

    #[test]
    fn keep_is_registered_by_default() {
        // A bare engine resolves "keep" with no explicit registration.
        let engine = AnonymizerEngine::new().silent();
        let mut ops = HashMap::new();
        ops.insert("EMAIL".to_string(), cfg(KEEP_NAME));
        let out = engine
            .anonymize("mail dev@acme.com", vec![rr("EMAIL", 5, 17)], &ops)
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("mail dev@acme.com"));
    }

    #[test]
    fn kept_span_surfaces_in_engine_items() {
        // The headline property: text is untouched, yet the span is on the
        // record. This is the whole point of `keep` over omitting the span.
        let engine = AnonymizerEngine::new().silent();
        let mut ops = HashMap::new();
        ops.insert("EMAIL".to_string(), cfg(KEEP_NAME));

        let text = "mail dev@acme.com now";
        let out = engine
            .anonymize(text, vec![rr("EMAIL", 5, 17)], &ops)
            .expect("anonymize");

        assert_eq!(out.text.as_deref(), Some(text), "text must be unchanged");
        assert_eq!(out.items.len(), 1, "kept span must still be reported");

        let item = out.items.first().expect("one item");
        assert_eq!(item.entity_type, "EMAIL");
        assert_eq!(item.operator.as_deref(), Some("keep"));
        assert_eq!(item.text.as_deref(), Some("dev@acme.com"));
    }

    #[test]
    fn keep_preserves_offsets() {
        // With no preceding replacement, a kept span's output offsets are
        // identical to its input offsets.
        let engine = AnonymizerEngine::new().silent();
        let mut ops = HashMap::new();
        ops.insert("EMAIL".to_string(), cfg(KEEP_NAME));

        let out = engine
            .anonymize("mail dev@acme.com now", vec![rr("EMAIL", 5, 17)], &ops)
            .expect("anonymize");

        let item = out.items.first().expect("one item");
        assert_eq!((item.start, item.end), (5, 17));
    }

    #[test]
    fn mixed_keep_and_replace_offsets_stay_aligned() {
        // A replacement *before* a kept span shifts that span's OUTPUT offsets
        // even though its text is untouched — the splice-alignment interaction
        // a pure no-op test cannot catch.
        let engine = AnonymizerEngine::new().silent();
        let mut ops = HashMap::new();
        ops.insert("EMAIL".to_string(), cfg(KEEP_NAME));
        // PHONE has no entry, so it falls back to `replace` -> "<PHONE>".

        let text = "call 555-0100 or mail dev@acme.com";
        let out = engine
            .anonymize(text, vec![rr("PHONE", 5, 13), rr("EMAIL", 22, 34)], &ops)
            .expect("anonymize");

        let anonymized = out.text.as_deref().expect("text");
        assert_eq!(anonymized, "call <PHONE> or mail dev@acme.com");

        let kept = out
            .items
            .iter()
            .find(|i| i.entity_type == "EMAIL")
            .expect("kept item");
        // "<PHONE>" (7 bytes) replaced "555-0100" (8 bytes), shifting the kept
        // span one byte earlier in the output.
        assert_eq!((kept.start, kept.end), (21, 33));
        // The reported offsets must actually index the kept text in the OUTPUT.
        assert_eq!(
            anonymized.get(kept.start..kept.end),
            Some("dev@acme.com"),
            "offsets must address the kept span in the output text"
        );
    }

    #[test]
    fn keep_and_deanonymize_keep_coexist_in_one_engine() {
        // Regression guard for the distinct-name decision: registering both
        // directions must leave BOTH reachable. A shared name would silently
        // evict the first registration.
        let engine = AnonymizerEngine::new()
            .with_operator(Box::new(DeanonymizeKeep::new()))
            .silent();

        let mut anon_ops = HashMap::new();
        anon_ops.insert("EMAIL".to_string(), cfg(KEEP_NAME));
        let anon = engine
            .anonymize("mail dev@acme.com", vec![rr("EMAIL", 5, 17)], &anon_ops)
            .expect("keep still registered");
        assert_eq!(
            anon.items.first().expect("item").operator.as_deref(),
            Some("keep")
        );

        let mut deanon_ops = HashMap::new();
        deanon_ops.insert("EMAIL".to_string(), cfg(KEEP_DEANONYMIZE_NAME));
        let deanon = engine
            .anonymize("mail dev@acme.com", vec![rr("EMAIL", 5, 17)], &deanon_ops)
            .expect("keep_deanonymize also registered");
        assert_eq!(
            deanon.items.first().expect("item").operator.as_deref(),
            Some("keep_deanonymize")
        );
    }
}
