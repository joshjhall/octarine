//! The [`Operator`] / [`AsyncOperator`] transformation contracts every
//! anonymize operator implements.
//!
//! An operator takes the text of a single detected span plus its
//! [`OperatorConfig`] and returns the replacement text. The
//! [`AnonymizerEngine`](crate::anonymize::AnonymizerEngine) owns the
//! orchestration (sorting, conflict resolution, offset tracking) and calls
//! operators one span at a time; operators themselves are pure and stateless.
//!
//! # Sync / async boundary (load-bearing invariant)
//!
//! There are two operator contracts and they are deliberately separate:
//!
//! - [`Operator`] is **synchronous** and applies a **fixed transform** — the
//!   replacement is a pure function of the span text and config (`replace`,
//!   `redact`, `mask`, a pure `custom` closure). It does **no I/O**.
//! - [`AsyncOperator`] is **asynchronous** and **session-aware** — it is handed
//!   an `&dyn StateStore` and a `&SessionId` so it can mint or reverse stable
//!   tokens through the vault (the `InstanceCounter` family in #543).
//!
//! > **Invariant:** the synchronous path only ever applies fixed transforms;
//! > vault ([`StateStore`](crate::anonymize::StateStore)) access is
//! > **async-only**.
//!
//! This is a documented assumption, not an accident. It keeps the
//! `observe/pii/redactor` (epic #604, "redaction == anonymization by
//! construction") fully synchronous, so the hot per-log-line path never has to
//! `block_on(...)` a store inside a tokio runtime — a panic/deadlock footgun —
//! and it avoids dual-colouring every pure primitive. If a synchronous caller
//! ever genuinely needs to read the vault, `StateStore` itself would need a
//! sync face; that is the trigger to revisit this split **deliberately** rather
//! than break it silently. See `docs/anonymize/token-vault.md`.
//!
//! # Implementing an operator
//!
//! ```
//! use octarine::anonymize::{Operator, OperatorConfig, OperatorType};
//! use octarine_problem::Result;
//!
//! /// An operator that upper-cases the matched span.
//! struct Shout;
//!
//! impl Operator for Shout {
//!     fn operate(
//!         &self,
//!         text: &str,
//!         _entity_type: &str,
//!         _config: &OperatorConfig,
//!     ) -> Result<String> {
//!         Ok(text.to_uppercase())
//!     }
//!
//!     fn operator_name(&self) -> &'static str {
//!         "shout"
//!     }
//! }
//!
//! let op = Shout;
//! let config = OperatorConfig::new("shout")?;
//! assert_eq!(op.operate("quiet", "NOTE", &config)?, "QUIET");
//! assert_eq!(op.operator_type(), OperatorType::Anonymize);
//! # Ok::<(), octarine_problem::Problem>(())
//! ```

use async_trait::async_trait;
use octarine_problem::Result;

use super::{OperatorConfig, OperatorType, SessionId, StateStore};

/// A pure, stateless transformation applied to one detected span.
///
/// Operators are registered with the
/// [`AnonymizerEngine`](crate::anonymize::AnonymizerEngine) by their
/// [`operator_name`](Operator::operate). The engine looks up the operator named
/// in each entity's [`OperatorConfig`], calls [`validate`](Operator::validate)
/// up front, then [`operate`](Operator::operate) during the rewrite.
///
/// Implementors must be `Send + Sync` so an engine can be shared across
/// threads.
pub trait Operator: Send + Sync {
    /// Transforms the matched span `text` into its replacement.
    ///
    /// `entity_type` is the label of the detected entity (e.g. `"US_SSN"`),
    /// supplied separately so the caller's [`OperatorConfig`] is never mutated.
    /// `config` carries operator-specific parameters.
    ///
    /// The returned string may be empty (a deletion), shorter, longer, or the
    /// same length as `text` — the engine recomputes output offsets either way.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](octarine_problem::Problem) if the transformation
    /// cannot be performed (for example, a parameter that passed
    /// [`validate`](Operator::validate) but proves unusable at apply time).
    fn operate(&self, text: &str, entity_type: &str, config: &OperatorConfig) -> Result<String>;

    /// Validates `config` before any span is processed.
    ///
    /// The engine calls this once per distinct operator config up front so that
    /// an invalid configuration fails fast — before the output text is
    /// partially built. The default implementation accepts any config; override
    /// it for operators with required or constrained parameters.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](octarine_problem::Problem) if `config` is invalid
    /// for this operator.
    fn validate(&self, config: &OperatorConfig) -> Result<()> {
        let _ = config;
        Ok(())
    }

    /// The canonical name used to register and look up this operator.
    ///
    /// Must match the `operator_name` callers place in an [`OperatorConfig`]
    /// (e.g. `"replace"`, `"redact"`). Lowercase by convention.
    fn operator_name(&self) -> &'static str;

    /// The direction this operator works in. Defaults to
    /// [`OperatorType::Anonymize`]; deanonymizers override it.
    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
}

/// A session-aware transformation that may read or write the token vault.
///
/// `AsyncOperator` is the asynchronous counterpart to [`Operator`]. Where a
/// sync operator applies a fixed transform with no I/O, an async operator is
/// handed an [`&dyn StateStore`](crate::anonymize::StateStore) and a
/// [`SessionId`] so it can mint a stable token for an original value (and find
/// the same token again on the next occurrence within the session) or reverse a
/// previously minted token back to its original. The store-backed
/// `InstanceCounter` operators (#543) implement this trait.
///
/// The [`AnonymizerEngine`](crate::anonymize::AnonymizerEngine) reaches async
/// operators only through
/// [`anonymize_async`](crate::anonymize::AnonymizerEngine::anonymize_async) and
/// [`deanonymize_async`](crate::anonymize::AnonymizerEngine::deanonymize_async),
/// which inject the store. The synchronous
/// [`anonymize`](crate::anonymize::AnonymizerEngine::anonymize) path never
/// touches an async operator or the vault — see the module-level invariant.
///
/// Implementors must be `Send + Sync` so an engine can be shared across
/// threads. The store and session are passed per call (rather than held by the
/// operator) so one operator instance serves every session and backend.
#[async_trait]
pub trait AsyncOperator: Send + Sync {
    /// Transforms the matched span `text` into its replacement, resolving any
    /// stable token through `store` within `session`.
    ///
    /// `entity_type` is the label of the detected entity (e.g. `"PERSON"`),
    /// supplied separately so the caller's [`OperatorConfig`] is never mutated.
    /// `config` carries operator-specific parameters. The returned string may be
    /// empty, shorter, longer, or the same length as `text` — the engine
    /// recomputes output offsets either way.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](octarine_problem::Problem) if the store I/O fails or
    /// the transformation cannot be performed.
    async fn operate_async(
        &self,
        text: &str,
        entity_type: &str,
        config: &OperatorConfig,
        store: &dyn StateStore,
        session: &SessionId,
    ) -> Result<String>;

    /// Validates `config` before any span is processed.
    ///
    /// Like [`Operator::validate`], the engine calls this once per distinct
    /// operator config up front so an invalid configuration fails fast. This
    /// method is **synchronous and must not touch the store** — it inspects
    /// config only. The default implementation accepts any config.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](octarine_problem::Problem) if `config` is invalid
    /// for this operator.
    fn validate(&self, config: &OperatorConfig) -> Result<()> {
        let _ = config;
        Ok(())
    }

    /// The canonical name used to register and look up this operator.
    ///
    /// Must match the `operator_name` callers place in an [`OperatorConfig`].
    /// Lowercase by convention. A name registered as an async operator shadows a
    /// sync operator of the same name on the async path.
    fn operator_name(&self) -> &'static str;

    /// The direction this operator works in. Defaults to
    /// [`OperatorType::Anonymize`]; deanonymizers override it.
    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
}
