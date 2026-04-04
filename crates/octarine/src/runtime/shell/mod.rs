//! Observable shell execution with xshell
//!
//! Wraps xshell with full octarine integration:
//! - Input validation via security/commands primitives
//! - Output redaction via observe/pii
//! - Metrics via observe/metrics
//!
//! # Security Model
//!
//! xshell executes commands via direct `execvp` (no shell interpretation).
//! Arguments are passed as an array, so shell metacharacters like `$(...)`,
//! backticks, pipes, and semicolons are **never interpreted** — they are
//! passed as literal strings to the target program.
//!
//! This means `ObservableCmd` offers two tiers of argument handling:
//!
//! - **`arg()` / `args()`** — Lenient mode. Detects dangerous patterns and
//!   logs warnings + metrics for audit trails, but still adds the argument.
//!   This is safe because xshell does not interpret the patterns. Use this
//!   when you want visibility into what arguments are being passed without
//!   blocking execution.
//!
//! - **`arg_validated()` / `args_validated()`** — Strict mode. Rejects
//!   arguments containing dangerous patterns by returning an error. Use this
//!   when arguments come from untrusted input and you want defense-in-depth
//!   regardless of the execution backend.
//!
//! # Example
//!
//! ```ignore
//! use octarine::runtime::shell::ObservableShell;
//!
//! let shell = ObservableShell::new()?;
//! let output = shell.cmd("git").args(["status", "--short"]).read()?;
//! ```

mod command;
mod context;

pub use command::ObservableCmd;
pub use context::ObservableShell;

use crate::observe::Problem;

/// Convert xshell error to Problem
pub(crate) fn xshell_error(err: xshell::Error) -> Problem {
    Problem::operation_failed(format!("shell command failed: {err}"))
}
