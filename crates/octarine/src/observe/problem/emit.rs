//! Inspection-time event dispatch for `Result<T, Problem>`.
//!
//! Counterpart to [`ProblemExt`](super::ProblemExt) (construct-time dispatch):
//! this restores the audit trail Layer-1 constructors previously emitted as a
//! side effect (issue #409), now that Layer 1 uses the event-free constructor
//! trait. Layer-3 wrappers call `result.emit_event(op, input)`, gated on the
//! builder's `emit_events` flag, to re-emit the event the primitive no longer
//! does.

use super::Problem;
use crate::observe;

/// Emit the observability event a failed `Result` warrants, keyed by the
/// [`Problem`] variant (the single source of the severity policy):
///
/// - [`Problem::PermissionDenied`] — a security detection (injection/override
///   attempt) → CRITICAL.
/// - [`Problem::Validation`] / [`Problem::Conversion`] — benign user-input
///   errors (empty, too long, bad chars, reserved names) → WARNING.
/// - `Ok(_)` and all other variants → no event.
pub(crate) trait EmitProblemEvent {
    /// Dispatch the event for this result's error, if any. `operation` is the
    /// audit operation name; `input` is echoed into the message as `(input: …)`.
    fn emit_event(&self, operation: &str, input: &str);
}

impl<T> EmitProblemEvent for Result<T, Problem> {
    fn emit_event(&self, operation: &str, input: &str) {
        match self {
            Err(Problem::PermissionDenied(reason)) => {
                observe::critical(operation, format!("{reason} (input: {input})"));
            }
            Err(Problem::Validation(reason) | Problem::Conversion(reason)) => {
                observe::warn(operation, format!("{reason} (input: {input})"));
            }
            _ => {}
        }
    }
}
