//! The [`Operator`] trait — the transformation contract every anonymize
//! operator implements.
//!
//! An operator takes the text of a single detected span plus its
//! [`OperatorConfig`] and returns the replacement text. The
//! [`AnonymizerEngine`](crate::anonymize::AnonymizerEngine) owns the
//! orchestration (sorting, conflict resolution, offset tracking) and calls
//! operators one span at a time; operators themselves are pure and stateless.
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

use octarine_problem::Result;

use super::{OperatorConfig, OperatorType};

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
